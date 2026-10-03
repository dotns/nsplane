//! The crypto worker pool: a hub and several spokes exchange numbered packets concurrently
//! in both directions, through a rekey and a peer removal under load. The same scenario runs
//! with the pool off as the reference and with the pool on: every packet is delivered, each
//! peer's sequence arrives in order, and handshakes, removals and drop counters behave the
//! same.

use std::collections::BTreeMap;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};

use nsplane::{
    ChannelTransport, DROP_SINK_FULL, DROP_TRANSMIT_FULL, Event, PacketBuf, Path, PeerId,
    TransportId, reasons,
};
use nsplane_e2e::{Events, Family, Node, Options, QUIET, TestResult, transfer, udp4};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// Key seed of the hub.
const HUB: u8 = 1;
/// Key seeds of the spokes.
const SPOKES: [u8; 4] = [2, 3, 4, 5];
/// The spoke that is removed under load.
const REMOVED: u8 = 5;
/// Packets each node sends to each of its peers per phase. What the hub receives in a phase
/// fits into its deliver queue alone (1024 packets), so no packet is dropped
/// however slowly the test reads them.
const PACKETS: u32 = 250;
/// Packets the removed spoke and the hub send each other in the removal phase, and what the
/// other spokes and the hub send each other meanwhile.
const REMOVAL_PACKETS: u32 = 800;
const LIGHT_PACKETS: u32 = 50;
/// Datagrams each link queues.
const LINK_CAPACITY: usize = 1024;
/// The hub's own transport id and address; unused, every link has its own.
const HUB_ID: TransportId = TransportId::new(1);
/// The transport id every spoke reaches the hub on.
const SPOKE_ID: TransportId = TransportId::new(1);

type Delivered = mpsc::Receiver<(PeerId, PacketBuf)>;
/// Sequence numbers received per phase and sender seed.
type Received = BTreeMap<u8, Vec<u32>>;

/// The hub's address on its link to spoke `seed`.
fn hub_addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, HUB], 1000 + u16::from(seed)))
}

/// The address of spoke `seed`.
fn spoke_addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 2000))
}

/// The tunnel address of the node with seed `seed`, as the harness assigns it.
const fn ip(seed: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, seed)
}

/// A hub on one link per spoke and the spokes, all peered, every engine with `workers`
/// crypto workers.
async fn star(workers: usize) -> TestResult<(Node<ChannelTransport>, Vec<Node<ChannelTransport>>)> {
    let mut hub_ends = Vec::new();
    let mut spokes = Vec::new();
    for seed in SPOKES {
        let (hub_end, spoke_end) = ChannelTransport::pair(
            LINK_CAPACITY,
            (TransportId::new(u16::from(seed)), hub_addr(seed)),
            (SPOKE_ID, spoke_addr(seed)),
        );
        hub_ends.push(hub_end);
        spokes.push(Node::<ChannelTransport>::with_builder(
            seed,
            SPOKE_ID,
            spoke_addr(seed),
            Options::default(),
            |b| b.transport(spoke_end).crypto_workers(workers),
        )?);
    }
    let hub = Node::<ChannelTransport>::with_builder(
        HUB,
        HUB_ID,
        hub_addr(HUB),
        Options::default(),
        |b| {
            hub_ends
                .into_iter()
                .fold(b, nsplane::EngineBuilder::transport)
                .crypto_workers(workers)
        },
    )?;
    for spoke in &spokes {
        let seed = spoke.ip4.octets()[3];
        hub.handle
            .add_or_update_peer(spoke.as_peer(TransportId::new(u16::from(seed))))
            .await?;
        let mut to_hub = hub.as_peer(SPOKE_ID);
        to_hub.path = Some(Path {
            addr: hub_addr(seed),
            ..spoke.path
        });
        spoke.handle.add_or_update_peer(to_hub).await?;
    }
    Ok((hub, spokes))
}

/// Numbered packet `n` of `phase` from `from` to `to`.
fn numbered(phase: u8, from: u8, to: u8, n: u32) -> Vec<u8> {
    let mut payload = vec![phase, from, to];
    payload.extend_from_slice(&n.to_be_bytes());
    udp4(ip(from), ip(to), &payload)
}

/// Sends packets `0..count` of `phase` from `from` to `to` through `local`.
fn flood(
    local: &mpsc::Sender<PacketBuf>,
    phase: u8,
    from: u8,
    to: u8,
    count: u32,
) -> JoinHandle<TestResult> {
    let local = local.clone();
    tokio::spawn(async move {
        for n in 0..count {
            let packet = numbered(phase, from, to, n);
            local.send(PacketBuf::from_packet(&packet)).await?;
        }
        Ok(())
    })
}

/// Collects the numbered packets of `phase` delivered to `seed` until nothing arrives for
/// [`QUIET`], then hands the receiver back.
fn collect(
    mut delivered: Delivered,
    phase: u8,
    seed: u8,
) -> JoinHandle<TestResult<(Delivered, Received)>> {
    tokio::spawn(async move {
        let mut received = Received::new();
        while let Ok(Some((_, packet))) = timeout(QUIET, delivered.recv()).await {
            // The payload behind the IPv4 and UDP headers.
            let Some(&[got, from, to, ref n @ ..]) = packet.as_packet().get(28..) else {
                return Err("not a numbered packet".into());
            };
            if (got, to) != (phase, seed) {
                return Err(format!("{seed} got packet {got}/{from}/{to} in phase {phase}").into());
            }
            let n = <[u8; 4]>::try_from(n)?;
            received
                .entry(from)
                .or_default()
                .push(u32::from_be_bytes(n));
        }
        Ok((delivered, received))
    })
}

/// Takes the delivery receivers of `nodes` and starts collecting from each.
fn collect_all<'a>(
    nodes: impl Iterator<Item = &'a mut Node<ChannelTransport>>,
    phase: u8,
) -> Vec<JoinHandle<TestResult<(Delivered, Received)>>> {
    nodes
        .map(|node| {
            let delivered = mem::replace(&mut node.delivered, mpsc::channel(1).1);
            collect(delivered, phase, node.ip4.octets()[3])
        })
        .collect()
}

/// Waits for the senders and the collectors, gives the receivers back to `nodes` and
/// returns what each node received, in the order of `nodes`.
async fn finish<'a>(
    senders: Vec<JoinHandle<TestResult>>,
    collectors: Vec<JoinHandle<TestResult<(Delivered, Received)>>>,
    nodes: impl Iterator<Item = &'a mut Node<ChannelTransport>>,
) -> TestResult<Vec<Received>> {
    for sender in senders {
        sender.await??;
    }
    let mut all = Vec::new();
    for (collector, node) in collectors.into_iter().zip(nodes) {
        let (delivered, received) = collector.await??;
        node.delivered = delivered;
        all.push(received);
    }
    Ok(all)
}

/// Checks that `received` is `0..count` in order, or with `prefix` an in-order prefix of it.
fn check_sequence(what: &str, received: &[u32], count: u32, prefix: bool) -> TestResult {
    let expected = u32::try_from(received.len())?;
    if !received.iter().copied().eq(0..expected) {
        let first = received
            .iter()
            .zip(0..)
            .find(|(n, i)| **n != *i)
            .map(|(n, i)| (i, *n));
        return Err(format!("{what}: out of order or lost, first mismatch {first:?}").into());
    }
    if !prefix && expected != count {
        return Err(format!("{what}: {expected} of {count} packets delivered").into());
    }
    Ok(())
}

/// One phase: every spoke and the hub flood each other with `PACKETS` packets while
/// `during` runs; every packet must arrive in order.
async fn phase<F>(
    hub: &mut Node<ChannelTransport>,
    spokes: &mut [Node<ChannelTransport>],
    number: u8,
    during: F,
) -> TestResult
where
    F: Future<Output = TestResult>,
{
    let mut senders = Vec::new();
    for spoke in spokes.iter() {
        let seed = spoke.ip4.octets()[3];
        senders.push(flood(&spoke.local, number, seed, HUB, PACKETS));
        senders.push(flood(&hub.local, number, HUB, seed, PACKETS));
    }
    let collectors = collect_all(std::iter::once(&mut *hub).chain(spokes.iter_mut()), number);
    during.await?;
    let received = finish(
        senders,
        collectors,
        std::iter::once(&mut *hub).chain(spokes.iter_mut()),
    )
    .await?;
    no_drops(hub, spokes, number).await?;
    for seed in SPOKES {
        let from_spoke = received[0].get(&seed).map_or(&[][..], Vec::as_slice);
        check_sequence(
            &format!("phase {number}: {seed} -> hub"),
            from_spoke,
            PACKETS,
            false,
        )?;
    }
    for (i, seed) in SPOKES.into_iter().enumerate() {
        let from_hub = received[i + 1].get(&HUB).map_or(&[][..], Vec::as_slice);
        check_sequence(
            &format!("phase {number}: hub -> {seed}"),
            from_hub,
            PACKETS,
            false,
        )?;
    }
    Ok(())
}

/// Fails if any node dropped a packet for want of room or failed to decrypt one.
async fn no_drops(
    hub: &Node<ChannelTransport>,
    spokes: &[Node<ChannelTransport>],
    phase: u8,
) -> TestResult {
    for node in std::iter::once(hub).chain(spokes) {
        for reason in [
            DROP_SINK_FULL,
            DROP_TRANSMIT_FULL,
            reasons::DECAPSULATE_ERROR,
        ] {
            let count = node.drops(reason).await?;
            if count > 0 {
                return Err(format!(
                    "phase {phase}: {} dropped {count} under {reason:?}",
                    node.ip4
                )
                .into());
            }
        }
    }
    Ok(())
}

/// How many handshakes `events` reports for `peer` until it is quiet.
async fn handshakes(events: &mut Events, peer: PeerId) -> TestResult<usize> {
    let mut count = 0;
    while events
        .expect_none(|e| matches!(e, Event::HandshakeCompleted { peer: p, .. } if *p == peer))
        .await
        .is_err()
    {
        count += 1;
    }
    Ok(count)
}

/// What the scenario observed, to compare the pool on with the pool off.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    /// Handshakes the hub completed with spokes 2 and 3 during the rekey phase.
    rekeys: (usize, usize),
    /// Whether the removed spoke is gone from the hub.
    removed: bool,
}

/// The whole scenario on engines with `workers` crypto workers.
async fn scenario(workers: usize) -> TestResult<Report> {
    let (mut hub, mut spokes) = star(workers).await?;

    // Sessions first: packets that two peers send each other before either has a session
    // start two handshakes at once, and the packets queued behind the losing one are lost.
    for spoke in &mut spokes {
        transfer(&hub, spoke, Family::V4, 64).await?;
        transfer(spoke, &mut hub, Family::V4, 64).await?;
    }
    phase(&mut hub, &mut spokes, 1, async { Ok(()) }).await?;

    // Rekeys under load: the hub starts one with spoke 2, spoke 3 one with the hub.
    let to_2 = hub.peer_of(&spokes[0]).await?;
    let to_3 = hub.peer_of(&spokes[1]).await?;
    // Every subscription sees every event: one counts each spoke's handshakes.
    let mut events_2 = hub.subscribe().await?;
    let mut events_3 = hub.subscribe().await?;
    let hub_handle = hub.handle.clone();
    let spoke_3 = spokes[1].handle.clone();
    let hub_key = hub.public();
    phase(&mut hub, &mut spokes, 2, async move {
        sleep(QUIET / 10).await;
        hub_handle.force_handshake(to_2, None).await?;
        let to_hub = spoke_3.peer_id(hub_key).await?.ok_or("unknown hub")?;
        spoke_3.force_handshake(to_hub, None).await?;
        Ok(())
    })
    .await?;
    let rekeys = (
        handshakes(&mut events_2, to_2).await?,
        handshakes(&mut events_3, to_3).await?,
    );

    // Removal under load: once traffic of the removed spoke flows, the hub removes it.
    let removed = spokes
        .iter()
        .position(|s| s.ip4.octets()[3] == REMOVED)
        .ok_or("no removed spoke")?;
    let removed_id = hub.peer_of(&spokes[removed]).await?;
    let removed_key = spokes[removed].public();
    let no_route = hub.drops(reasons::NO_ROUTE).await?;
    let unknown_session = hub.drops(reasons::UNKNOWN_SESSION).await?;
    let mut senders = Vec::new();
    for spoke in &spokes {
        let seed = spoke.ip4.octets()[3];
        let count = if seed == REMOVED {
            REMOVAL_PACKETS
        } else {
            LIGHT_PACKETS
        };
        senders.push(flood(&spoke.local, 3, seed, HUB, count));
        senders.push(flood(&hub.local, 3, HUB, seed, count));
    }
    let collectors = collect_all(std::iter::once(&mut hub).chain(spokes.iter_mut()), 3);
    loop {
        let stats = hub
            .handle
            .peer_stats(removed_id)
            .await?
            .ok_or("removed early")?;
        if stats.data_rx > 0 {
            break;
        }
        sleep(QUIET / 100).await;
    }
    hub.handle.remove_peer(removed_key).await?;
    let received = finish(
        senders,
        collectors,
        std::iter::once(&mut hub).chain(spokes.iter_mut()),
    )
    .await?;
    no_drops(&hub, &spokes, 3).await?;
    for (i, spoke) in spokes.iter().enumerate() {
        let seed = spoke.ip4.octets()[3];
        let from_spoke = received[0].get(&seed).map_or(&[][..], Vec::as_slice);
        let from_hub = received[i + 1].get(&HUB).map_or(&[][..], Vec::as_slice);
        if seed == REMOVED {
            check_sequence("removal: removed -> hub", from_spoke, REMOVAL_PACKETS, true)?;
            check_sequence("removal: hub -> removed", from_hub, REMOVAL_PACKETS, true)?;
            // Every packet is either delivered or counted: after the removal, the hub knows
            // neither the spoke's session nor a route to it.
            let unknown = hub.drops(reasons::UNKNOWN_SESSION).await? - unknown_session;
            let unrouted = hub.drops(reasons::NO_ROUTE).await? - no_route;
            assert_eq!(
                from_spoke.len() as u64 + unknown,
                u64::from(REMOVAL_PACKETS)
            );
            assert_eq!(from_hub.len() as u64 + unrouted, u64::from(REMOVAL_PACKETS));
        } else {
            let what = format!("removal: {seed} -> hub");
            check_sequence(&what, from_spoke, LIGHT_PACKETS, false)?;
            let what = format!("removal: hub -> {seed}");
            check_sequence(&what, from_hub, LIGHT_PACKETS, false)?;
        }
    }
    let removed = hub.handle.peer_stats(removed_id).await?.is_none();
    Ok(Report { rekeys, removed })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pool_keeps_every_peer_in_order_like_the_owner_task() -> TestResult {
    let reference = scenario(0).await?;
    assert_eq!(reference.rekeys, (1, 1), "one rekey with each spoke");
    assert!(reference.removed);
    let pooled = scenario(4).await?;
    assert_eq!(pooled, reference);
    Ok(())
}
