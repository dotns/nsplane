//! The engine's local barrier and its validated plaintext ingress.
//!
//! Barrier: node `a`'s outbound filter can hold the owner task inside its call, so local
//! packets pile up behind it in the engine's local queue and in the source task; a barrier
//! taken then completes only once every one of them passed the filter (recorded in order),
//! with the fragmentation stage and with crypto workers too, after a suspension only once
//! resumed, and never once the engine stopped.
//!
//! Plaintext ingress: node `b` takes plaintext packets attributed to its peer `a` and runs
//! them through the checks and filters of decrypted data; its queue is bounded and refuses
//! once the engine stopped.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use nsplane::{
    ChannelTransport, EngineBuilder, EngineError, FragmentConfig, PacketFilter, PeerId,
    PlaintextIngress, PlaintextRefused, reasons,
};
use nsplane_core::Verdict;
use nsplane_e2e::{
    Events, Node, Options, QUIET, SharedFilter, TestResult, WAIT, channel_pair_with, introduce,
    payload, udp4,
};
use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::{Ecn, PacketBuf, Path, TransportId};
use tokio::time::{sleep, timeout};

/// An outbound filter that records the IPv4 identification of every packet it passes and
/// holds the caller while it has no credit; open, it has unlimited credit.
#[derive(Debug)]
struct Gate {
    credit: Mutex<usize>,
    granted: Condvar,
    /// How many times a packet started waiting for credit.
    waits: AtomicUsize,
    passed: Mutex<Vec<u16>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            credit: Mutex::new(usize::MAX),
            granted: Condvar::new(),
            waits: AtomicUsize::new(0),
            passed: Mutex::new(Vec::new()),
        }
    }
}

impl Gate {
    fn close(&self) {
        *self.credit.lock().unwrap() = 0;
    }

    fn open(&self) {
        *self.credit.lock().unwrap() = usize::MAX;
        self.granted.notify_all();
    }

    /// Lets `n` more packets pass.
    fn allow(&self, n: usize) {
        let mut credit = self.credit.lock().unwrap();
        *credit = credit.saturating_add(n);
        self.granted.notify_all();
    }

    /// Waits until packets started waiting for credit `n` times in all.
    async fn waited(&self, n: usize) -> TestResult {
        timeout(WAIT, async {
            while self.waits.load(Ordering::Acquire) < n {
                sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }

    fn passed(&self) -> Vec<u16> {
        self.passed.lock().unwrap().clone()
    }
}

impl PacketFilter for Gate {
    fn inbound(&self, _: PeerId, _: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }

    fn outbound(&self, _: PeerId, packet: &mut PacketBuf) -> Verdict {
        let mut credit = self.credit.lock().unwrap();
        if *credit == 0 {
            self.waits.fetch_add(1, Ordering::Release);
        }
        while *credit == 0 {
            credit = self.granted.wait(credit).unwrap();
        }
        if *credit != usize::MAX {
            *credit -= 1;
        }
        drop(credit);
        let p = packet.as_packet();
        self.passed
            .lock()
            .unwrap()
            .push(u16::from_be_bytes([p[4], p[5]]));
        Verdict::Accept
    }
}

/// Opens the gate when dropped, so a failing test never leaves the owner task held.
struct Opens(Arc<Gate>);

impl std::ops::Deref for Opens {
    type Target = Gate;

    fn deref(&self) -> &Gate {
        &self.0
    }
}

impl Drop for Opens {
    fn drop(&mut self) {
        self.0.open();
    }
}

/// How `a` is built for a barrier test.
#[derive(Debug, Clone, Copy)]
struct Setup {
    fragmenter: bool,
    crypto_workers: usize,
    queue_capacity: usize,
}

const PLAIN: Setup = Setup {
    fragmenter: false,
    crypto_workers: 0,
    queue_capacity: 1024,
};

/// Peers `a` (with the gate) and `b`, with a session.
async fn gated(
    setup: Setup,
) -> TestResult<(Node<ChannelTransport>, Node<ChannelTransport>, Opens)> {
    let gate = Arc::new(Gate::default());
    let (a, mut b) = channel_pair_with(Options::default(), |seed, builder| {
        if seed != 1 {
            return builder;
        }
        let mut builder = builder
            .filter(Box::new(SharedFilter(Arc::clone(&gate))))
            .crypto_workers(setup.crypto_workers)
            .queue_capacity(setup.queue_capacity);
        if setup.fragmenter {
            builder = builder.fragmenter(FragmentConfig::default());
        }
        builder
    })?;
    introduce(&a, &b, None).await?;
    a.send(&packet(&a, &b, 0, 64)).await?;
    b.expect_delivery().await?;
    gate.passed.lock().unwrap().clear();
    Ok((a, b, Opens(gate)))
}

/// A UDP packet of `len` payload bytes from `a` to `b` with IPv4 identification `id`, which
/// the fragmentation stage may split.
fn packet(a: &Node<ChannelTransport>, b: &Node<ChannelTransport>, id: u16, len: usize) -> Vec<u8> {
    let mut packet = udp4(a.ip4, b.ip4, &payload(len));
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6] = 0;
    packet[10..12].fill(0);
    let sum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// Closes the gate and sends packet 1, which then holds `a`'s owner task in the filter.
async fn hold_the_owner(
    a: &Node<ChannelTransport>,
    b: &Node<ChannelTransport>,
    gate: &Gate,
) -> TestResult {
    gate.close();
    a.send(&packet(a, b, 1, 64)).await?;
    gate.waited(1).await
}

/// Sends packets `ids` and waits until the source task took all but `left` of them from the
/// source (a channel source reads one packet at a time).
async fn send_taken(
    a: &Node<ChannelTransport>,
    b: &Node<ChannelTransport>,
    ids: std::ops::RangeInclusive<u16>,
    len: usize,
    left: usize,
) -> TestResult {
    for id in ids {
        a.send(&packet(a, b, id, len)).await?;
    }
    timeout(WAIT, async {
        while a.local.max_capacity() - a.local.capacity() > left {
            sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await?;
    // The source task counts what a read returned right after the read.
    sleep(QUIET).await;
    Ok(())
}

/// Whether `future` is still pending after [`QUIET`]. Polled on the test's own thread: a
/// spawned task woken by the owner task could wait behind the owner's held worker thread.
async fn pending<F: Future + Unpin>(future: &mut F) -> bool {
    timeout(QUIET, future).await.is_err()
}

/// Every packet sent before the barrier passed the filter before it returned.
async fn barrier_after_queued_packets(setup: Setup, len: usize, copies: usize) -> TestResult {
    let (a, b, gate) = gated(setup).await?;
    hold_the_owner(&a, &b, &gate).await?;
    send_taken(&a, &b, 2..=20, len, 0).await?;

    let barrier = a.handle.local_barrier();
    tokio::pin!(barrier);
    assert!(
        pending(&mut barrier).await,
        "the barrier waits for the held packets"
    );
    // Packet 1 passes, then the owner serves the barrier and is held again on packet 2.
    gate.allow(1);
    gate.waited(2).await?;
    assert!(
        pending(&mut barrier).await,
        "packets 2 to 20 have not passed"
    );
    assert_eq!(gate.passed(), [1]);
    gate.open();
    timeout(WAIT, barrier).await??;
    let passed = gate.passed();
    let expected: Vec<u16> = (1..=20)
        .flat_map(|id| std::iter::repeat_n(id, if id == 1 { 1 } else { copies }))
        .collect();
    assert_eq!(passed, expected, "{setup:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_barrier_waits_for_queued_local_packets() -> TestResult {
    barrier_after_queued_packets(PLAIN, 64, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_barrier_waits_for_fragments() -> TestResult {
    let setup = Setup {
        fragmenter: true,
        ..PLAIN
    };
    // Above the source MTU of 1420: two fragments each.
    barrier_after_queued_packets(setup, 2000, 2).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_barrier_waits_with_crypto_workers() -> TestResult {
    let setup = Setup {
        crypto_workers: 2,
        ..PLAIN
    };
    barrier_after_queued_packets(setup, 64, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_barrier_counts_the_packet_the_source_task_holds() -> TestResult {
    // A local queue of 4: packets 2 to 5 fill it, the source task holds packet 6 while it
    // waits for room, and packets 7 to 20 stay in the source, not taken.
    let setup = Setup {
        queue_capacity: 4,
        ..PLAIN
    };
    let (a, b, gate) = gated(setup).await?;
    hold_the_owner(&a, &b, &gate).await?;
    send_taken(&a, &b, 2..=20, 64, 14).await?;
    sleep(QUIET).await;
    assert_eq!(a.local.max_capacity() - a.local.capacity(), 14);

    let barrier = a.handle.local_barrier();
    tokio::pin!(barrier);
    assert!(
        pending(&mut barrier).await,
        "the barrier waits for the held packets"
    );
    // Packets 1 to 5 pass, the owner is held on packet 6, the one the source task held.
    gate.allow(5);
    gate.waited(2).await?;
    assert!(pending(&mut barrier).await, "packet 6 has not passed");
    assert_eq!(gate.passed(), [1, 2, 3, 4, 5]);
    gate.open();
    timeout(WAIT, barrier).await??;
    let passed = gate.passed();
    assert!(passed.len() >= 6, "{passed:?}");
    assert_eq!(passed[..6], [1, 2, 3, 4, 5, 6]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_engine_passes_the_barrier_at_once() -> TestResult {
    let (a, _b, _gate) = gated(PLAIN).await?;
    timeout(WAIT, a.handle.local_barrier()).await??;
    a.handle.shutdown().await?;
    assert_eq!(a.handle.local_barrier().await, Err(EngineError));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suspended_engine_passes_the_barrier_after_resuming() -> TestResult {
    let (a, b, gate) = gated(PLAIN).await?;
    hold_the_owner(&a, &b, &gate).await?;
    send_taken(&a, &b, 2..=5, 64, 0).await?;
    // Queued behind the held packet: the suspension, then the barrier.
    let handle = a.handle.clone();
    let suspend = tokio::spawn(async move { handle.suspend().await });
    sleep(QUIET).await;
    let barrier = a.handle.local_barrier();
    tokio::pin!(barrier);
    assert!(pending(&mut barrier).await);
    gate.open();
    timeout(WAIT, suspend).await???;
    assert!(
        pending(&mut barrier).await,
        "suspended with packets 2 to 5 queued"
    );
    assert_eq!(gate.passed(), [1]);
    a.handle.resume().await?;
    timeout(WAIT, barrier).await??;
    assert_eq!(gate.passed(), [1, 2, 3, 4, 5]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_engine_never_passes_the_barrier() -> TestResult {
    let (a, b, gate) = gated(PLAIN).await?;
    hold_the_owner(&a, &b, &gate).await?;
    send_taken(&a, &b, 2..=5, 64, 0).await?;
    // Queued behind the held packet: the barrier, then the shutdown, which the owner serves
    // before the queued local packets.
    let barrier = a.handle.local_barrier();
    tokio::pin!(barrier);
    assert!(pending(&mut barrier).await);
    let handle = a.handle.clone();
    let shutdown = tokio::spawn(async move { handle.shutdown().await });
    sleep(QUIET).await;
    gate.open();
    timeout(WAIT, shutdown).await???;
    assert_eq!(timeout(WAIT, barrier).await?, Err(EngineError));
    Ok(())
}

/// Records the peer and arrival path of every decrypted packet it sees; drops packets whose
/// last byte is 1.
#[derive(Debug, Default)]
struct Inbound(Mutex<Vec<(PeerId, Path)>>);

const FILTER_DROP: &str = "dropped by the test filter";

impl PacketFilter for Inbound {
    fn inbound(&self, _: PeerId, _: &mut PacketBuf) -> Verdict {
        unreachable!("the engine calls inbound_from")
    }

    fn inbound_from(&self, peer: PeerId, from: &Path, packet: &mut PacketBuf) -> Verdict {
        self.0.lock().unwrap().push((peer, *from));
        if packet.as_packet().last() == Some(&1) {
            Verdict::Drop {
                reason: FILTER_DROP,
            }
        } else {
            Verdict::Accept
        }
    }

    fn outbound(&self, _: PeerId, _: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }
}

/// Peers `a` and `b`, `b` with a plaintext ingress of `capacity` and the inbound filter;
/// no session.
async fn ingress_pair(
    capacity: usize,
) -> TestResult<(
    Node<ChannelTransport>,
    Node<ChannelTransport>,
    PlaintextIngress,
    Arc<Inbound>,
)> {
    let filter = Arc::new(Inbound::default());
    let mut ingress = None;
    let (a, b) = channel_pair_with(Options::default(), |seed, builder: EngineBuilder<_, _>| {
        if seed != 2 {
            return builder;
        }
        let (builder, entry) = builder
            .filter(Box::new(SharedFilter(Arc::clone(&filter))))
            .plaintext_ingress(capacity);
        ingress = Some(entry);
        builder
    })?;
    introduce(&a, &b, None).await?;
    Ok((a, b, ingress.unwrap(), filter))
}

/// The path a reference data path says a plaintext packet arrived on.
fn reference_path() -> Path {
    Path {
        transport: TransportId::new(9),
        addr: SocketAddr::from(([198, 51, 100, 9], 9)),
        ecn: Ecn::NotEct,
    }
}

#[tokio::test]
async fn plaintext_is_checked_like_decrypted_data() -> TestResult {
    let (a, mut b, ingress, filter) = ingress_pair(16).await?;
    let mut events: Events = b.subscribe().await?;
    let peer = b.peer_of(&a).await?;
    let before = b.handle.peer_stats(peer).await?.unwrap();

    let accepted = udp4(a.ip4, b.ip4, &payload(64));
    ingress
        .send(peer, reference_path(), PacketBuf::from_packet(&accepted))
        .await?;
    assert_eq!(b.expect_delivery().await?, (peer, accepted.clone()));
    assert_eq!(filter.0.lock().unwrap().clone(), [(peer, reference_path())]);

    // A source outside `a`'s allowed IPs, a filter drop and an unknown peer.
    let spoofed = udp4([10, 0, 0, 99].into(), b.ip4, &payload(64));
    ingress
        .send(peer, reference_path(), PacketBuf::from_packet(&spoofed))
        .await?;
    let mut dropped = udp4(a.ip4, b.ip4, &payload(64));
    *dropped.last_mut().unwrap() = 1;
    ingress
        .try_send(peer, reference_path(), PacketBuf::from_packet(&dropped))
        .unwrap();
    let unknown = PeerId::new(peer.get() + 100);
    ingress
        .send(unknown, reference_path(), PacketBuf::from_packet(&accepted))
        .await?;
    b.expect_no_delivery().await?;
    assert_eq!(b.drops(reasons::SOURCE_NOT_ALLOWED).await?, 1);
    assert_eq!(b.drops(FILTER_DROP).await?, 1);
    assert_eq!(b.drops(reasons::UNKNOWN_PLAINTEXT_PEER).await?, 1);

    // Nothing was authenticated: no event about the peer's path, which stays.
    events
        .expect_none(|event| {
            matches!(
                event,
                nsplane::Event::Authenticated { .. } | nsplane::Event::PathAdopted { .. }
            )
        })
        .await?;
    let after = b.handle.peer_stats(peer).await?.unwrap();
    assert_eq!(after.path, before.path);
    assert_eq!(after.rx, before.rx);
    assert_eq!(after.data_rx, before.data_rx + accepted.len() as u64);
    assert_eq!(after.last_handshake, None);
    Ok(())
}

#[tokio::test]
async fn the_plaintext_queue_is_bounded() -> TestResult {
    let (a, mut b, ingress, _) = ingress_pair(2).await?;
    let peer = b.peer_of(&a).await?;
    let (src, dst) = (a.ip4, b.ip4);
    // Payload bytes other than 1, which the filter drops.
    let packet = |n: u8| PacketBuf::from_packet(&udp4(src, dst, &[n + 10; 16]));
    // A suspended engine takes nothing from the queue.
    b.handle.suspend().await?;
    ingress.try_send(peer, reference_path(), packet(1)).unwrap();
    ingress.try_send(peer, reference_path(), packet(2)).unwrap();
    match ingress.try_send(peer, reference_path(), packet(3)) {
        Err(PlaintextRefused::Full(refused)) => {
            assert_eq!(refused.as_packet(), packet(3).as_packet());
        }
        other => panic!("expected a full queue, got {other:?}"),
    }
    let waiting = {
        let ingress = ingress.clone();
        let packet = packet(3);
        tokio::spawn(async move { ingress.send(peer, reference_path(), packet).await })
    };
    sleep(QUIET).await;
    assert!(!waiting.is_finished(), "send waits while the queue is full");

    b.handle.resume().await?;
    timeout(WAIT, waiting).await???;
    for n in 1..=3 {
        let (from, delivered) = b.expect_delivery().await?;
        assert_eq!(from, peer);
        assert_eq!(delivered, packet(n).as_packet());
    }
    Ok(())
}

#[tokio::test]
async fn the_plaintext_ingress_refuses_once_the_engine_stopped() -> TestResult {
    let (a, b, ingress, _) = ingress_pair(4).await?;
    let peer = b.peer_of(&a).await?;
    let packet = PacketBuf::from_packet(&udp4(a.ip4, b.ip4, &payload(16)));
    b.handle.shutdown().await?;
    assert_eq!(
        ingress.send(peer, reference_path(), packet.clone()).await,
        Err(EngineError)
    );
    match ingress.try_send(peer, reference_path(), packet) {
        Err(PlaintextRefused::Stopped(_)) => {}
        other => panic!("expected a stopped engine, got {other:?}"),
    }
    Ok(())
}
