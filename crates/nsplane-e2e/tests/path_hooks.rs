//! The hooks a path ladder drives the engine with (ns account mode, quick-v2 §9): sending
//! one packet on an explicit path (`EngineHandle::inject_outbound_on`), the path a decrypted
//! packet arrived on in the inbound filters (`PacketFilter::inbound_from`), and a policy that
//! observes every authenticated message (`PathPolicy::observe_every_message`).
//!
//! Two engines are linked twice over channel transports: link 1 carries the peers' paths,
//! link 2 is the "candidate" a probe goes to.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use nsplane::{
    ChannelTransport, Event, PacketBuf, PacketFilter, Path, PathPolicy, PeerId, TransportId,
    reasons,
};
use nsplane_core::{MessageKind, Roam, Verdict};
use nsplane_e2e::{
    Family, Node, Options, SharedFilter, TestResult, exchange, introduce, payload, transfer,
};

const A1: TransportId = TransportId::new(1);
const B1: TransportId = TransportId::new(2);
const A2: TransportId = TransportId::new(3);
const B2: TransportId = TransportId::new(4);

fn addr(last: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], port))
}

/// Address of `a` on link 1 and link 2, and of `b` on both.
fn a1() -> SocketAddr {
    addr(1, 1001)
}
fn a2() -> SocketAddr {
    addr(1, 1002)
}
fn b1() -> SocketAddr {
    addr(2, 2001)
}
fn b2() -> SocketAddr {
    addr(2, 2002)
}

const fn path(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: nsplane::Ecn::NotEct,
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records the path of every decrypted packet.
#[derive(Debug, Default)]
struct Arrivals(Mutex<Vec<(PeerId, Path)>>);

impl PacketFilter for Arrivals {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Drop {
            reason: "inbound called instead of inbound_from",
        }
    }

    fn inbound_from(&self, peer: PeerId, from: &Path, _packet: &mut PacketBuf) -> Verdict {
        lock(&self.0).push((peer, *from));
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }
}

/// Standard roaming that records what it is asked about.
#[derive(Debug, Default)]
struct Observer {
    every_message: bool,
    calls: Mutex<Vec<(PeerId, Path, MessageKind)>>,
}

/// Hands an `Arc<Observer>` to the engine.
#[derive(Debug)]
struct SharedObserver(Arc<Observer>);

impl PathPolicy for SharedObserver {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        None
    }

    fn on_authenticated(&self, peer: PeerId, from: &Path, kind: MessageKind) -> Roam {
        lock(&self.0.calls).push((peer, *from, kind));
        Roam::Adopt
    }

    fn observe_every_message(&self) -> bool {
        self.0.every_message
    }
}

/// `a` (seed 1) and `b` (seed 2), linked twice, peers of each other over link 1. `b` records
/// its arrivals; `a` runs `policy`, and both run `workers` crypto workers.
fn linked(
    policy: Option<Arc<Observer>>,
    workers: usize,
) -> TestResult<(
    Node<ChannelTransport>,
    Node<ChannelTransport>,
    Arc<Arrivals>,
)> {
    let (link_a1, link_b1) = ChannelTransport::pair(256, (A1, a1()), (B1, b1()));
    let (link_a2, link_b2) = ChannelTransport::pair(256, (A2, a2()), (B2, b2()));
    let arrivals = Arc::new(Arrivals::default());
    let a = Node::with_builder(1, A1, a1(), Options::default(), |builder| {
        let builder = builder
            .transport(link_a1)
            .transport(link_a2)
            .crypto_workers(workers);
        match policy {
            Some(policy) => builder.policy(Box::new(SharedObserver(policy))),
            None => builder,
        }
    })?;
    let filter = Arc::clone(&arrivals);
    let b = Node::with_builder(2, B1, b1(), Options::default(), |builder| {
        builder
            .transport(link_b1)
            .transport(link_b2)
            .crypto_workers(workers)
            .filter(Box::new(SharedFilter(filter)))
    })?;
    Ok((a, b, arrivals))
}

/// A probe from `a` to `b` on link 2 arrives there, while `a` keeps `b` on link 1.
async fn probe_on_the_candidate(workers: usize) -> TestResult {
    let (mut a, mut b, arrivals) = linked(None, workers)?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    let to_b = a.peer_of(&b).await?;
    let from_a = b.peer_of(&a).await?;
    assert!(
        lock(&arrivals.0)
            .iter()
            .all(|&(peer, from)| peer == from_a && from == path(B1, a1())),
        "{:?}",
        lock(&arrivals.0)
    );

    let probe = a.packet_to(&b, Family::V4, &payload(1172));
    a.handle
        .inject_outbound_on(to_b, path(A2, b2()), PacketBuf::from_packet(&probe))
        .await?;
    let (peer, delivered) = b.expect_delivery().await?;
    assert_eq!((peer, delivered), (from_a, probe));
    assert_eq!(lock(&arrivals.0).last(), Some(&(from_a, path(B2, a2()))));

    let stats = a.handle.peer_stats(to_b).await?.ok_or("peer")?;
    assert_eq!(stats.path, Some(path(A1, b1())));
    assert_eq!(a.drops(reasons::NO_SESSION).await?, 0);
    Ok(())
}

#[tokio::test]
async fn a_probe_leaves_on_its_path_and_the_receiver_sees_where_it_came_from() -> TestResult {
    probe_on_the_candidate(0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_leaves_on_its_path_with_crypto_workers() -> TestResult {
    probe_on_the_candidate(2).await
}

#[tokio::test]
async fn a_probe_without_a_session_is_dropped() -> TestResult {
    let (a, mut b, _) = linked(None, 0)?;
    introduce(&a, &b, None).await?;
    let to_b = a.peer_of(&b).await?;
    let probe = a.packet_to(&b, Family::V4, &payload(64));
    a.handle
        .inject_outbound_on(to_b, path(A2, b2()), PacketBuf::from_packet(&probe))
        .await?;
    assert_eq!(a.drops(reasons::NO_SESSION).await?, 1);
    // No handshake started towards the probe path or the peer's path.
    b.expect_no_delivery().await?;
    let stats = a.handle.peer_stats(to_b).await?.ok_or("peer")?;
    assert_eq!((stats.tx, stats.last_handshake), (0, None));

    a.handle
        .inject_outbound_on(
            PeerId::new(999),
            path(A2, b2()),
            PacketBuf::from_packet(&probe),
        )
        .await?;
    // An unknown peer is ignored, as by `force_handshake`.
    assert_eq!(a.drops(reasons::NO_SESSION).await?, 1);
    Ok(())
}

#[tokio::test]
async fn an_observing_policy_is_told_about_every_message_on_the_current_path() -> TestResult {
    let observer = Arc::new(Observer {
        every_message: true,
        ..Observer::default()
    });
    let (mut a, mut b, _) = linked(Some(Arc::clone(&observer)), 0)?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    let from_b = a.peer_of(&b).await?;
    lock(&observer.calls).clear();
    let mut events = a.subscribe().await?;

    for _ in 0..5 {
        transfer(&b, &mut a, Family::V4, 100).await?;
    }
    let on_current = lock(&observer.calls)
        .iter()
        .filter(|&&(peer, from, kind)| {
            peer == from_b && from == path(A1, b1()) && kind == MessageKind::Data
        })
        .count();
    assert_eq!(on_current, 5, "{:?}", lock(&observer.calls));
    // Still no `Authenticated` event for messages on the current path.
    events
        .expect_none(|e| matches!(e, Event::Authenticated { .. }))
        .await?;
    Ok(())
}

#[tokio::test]
async fn a_default_policy_is_asked_only_about_other_paths() -> TestResult {
    let observer = Arc::new(Observer::default());
    let (mut a, mut b, _) = linked(Some(Arc::clone(&observer)), 0)?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    lock(&observer.calls).clear();
    for _ in 0..5 {
        transfer(&b, &mut a, Family::V4, 100).await?;
    }
    assert!(
        lock(&observer.calls).is_empty(),
        "{:?}",
        lock(&observer.calls)
    );
    Ok(())
}
