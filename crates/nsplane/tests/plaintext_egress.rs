//! Plaintext egress through the engine: the local packets routed to a marked peer reach the
//! `PlaintextEgress` receiver after the outbound filters instead of being sealed; the mark is
//! runtime state of the `PeerId`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

mod support;

use std::sync::{Arc, Mutex};

use nsplane::{
    AllowedIp, DROP_PLAINTEXT_EGRESS_CLOSED, DROP_PLAINTEXT_EGRESS_FULL, Event, PacketBuf,
    PacketFilter, PeerId,
};
use nsplane_core::Verdict;
use support::{IP_A, IP_B, Node, Setup, WAIT, connected, eventually, ipv4, pair, tag};
use tokio::time::timeout;

/// The packet `a` sends to `b` carrying `payload`.
fn local(payload: &[u8]) -> PacketBuf {
    PacketBuf::from_packet(&ipv4(IP_A, IP_B, payload))
}

/// The next packet `a`'s plaintext egress receives.
async fn egress(a: &mut Node) -> (PeerId, Vec<u8>) {
    let egress = a.egress.as_mut().unwrap();
    let (to, packet) = timeout(WAIT, egress.recv()).await.unwrap().unwrap();
    (to, packet.as_packet().to_vec())
}

/// Counts the local packets it sees.
#[derive(Debug, Default)]
struct Count(Mutex<usize>);

#[derive(Debug)]
struct Counting(Arc<Count>);

impl PacketFilter for Counting {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        *self.0.0.lock().unwrap() += 1;
        Verdict::Accept
    }
}

#[tokio::test]
async fn a_marked_peer_gets_its_packets_after_the_filters_as_plaintext() {
    for workers in [0, 2] {
        let count = Arc::new(Count::default());
        let (mut a, mut b, _script) = connected(Setup {
            workers,
            egress: Some(8),
            filters: vec![Box::new(Counting(Arc::clone(&count)))],
            ..Setup::default()
        })
        .await;
        let peer = a.peer_of(&b).await;
        assert!(a.handle.set_plaintext_egress(peer, true).await.unwrap());
        let mut packet = local(b"plain");
        packet.set_tag(Some(tag(3)));
        packet.set_tracked(true);
        a.send(packet).await;
        let egress_rx = a.egress.as_mut().unwrap();
        let (to, packet) = timeout(WAIT, egress_rx.recv()).await.unwrap().unwrap();
        assert_eq!(to, peer);
        assert_eq!(packet.as_packet(), ipv4(IP_A, IP_B, b"plain"));
        assert_eq!(packet.tag(), Some(tag(3)));
        assert!(!packet.is_tracked());
        assert_eq!(*count.0.lock().unwrap(), 1);
        b.expect_no_delivery().await;

        // Unmarked again: sealed.
        assert!(a.handle.set_plaintext_egress(peer, false).await.unwrap());
        a.send(local(b"sealed")).await;
        assert_eq!(b.expect_delivery().await.1, ipv4(IP_A, IP_B, b"sealed"));
    }
}

#[tokio::test]
async fn a_full_queue_drops_and_counts() {
    let (a, b, _script) = connected(Setup {
        egress: Some(1),
        ..Setup::default()
    })
    .await;
    let peer = a.peer_of(&b).await;
    a.handle.set_plaintext_egress(peer, true).await.unwrap();
    for i in 0..3u8 {
        a.send(local(&[i])).await;
    }
    eventually(|| async { a.drops(DROP_PLAINTEXT_EGRESS_FULL).await == 2 }).await;
}

#[tokio::test]
async fn a_closed_or_missing_receiver_drops_and_counts() {
    for built in [true, false] {
        let (mut a, b, _script) = connected(Setup {
            egress: built.then_some(4),
            ..Setup::default()
        })
        .await;
        drop(a.egress.take());
        let peer = a.peer_of(&b).await;
        a.handle.set_plaintext_egress(peer, true).await.unwrap();
        a.send(local(b"nowhere")).await;
        eventually(|| async { a.drops(DROP_PLAINTEXT_EGRESS_CLOSED).await == 1 }).await;
        let mut events = a.handle.subscribe().await.unwrap();
        a.send(local(b"nowhere")).await;
        let event = timeout(WAIT, events.recv()).await.unwrap().unwrap();
        assert_eq!(
            event,
            Event::Dropped {
                peer: Some(peer),
                reason: DROP_PLAINTEXT_EGRESS_CLOSED,
            }
        );
    }
}

#[tokio::test]
async fn the_mark_is_kept_across_an_update_and_absent_after_remove_and_re_add() {
    let (mut a, mut b, _script) = connected(Setup {
        egress: Some(8),
        ..Setup::default()
    })
    .await;
    let peer = a.peer_of(&b).await;
    a.handle.set_plaintext_egress(peer, true).await.unwrap();
    // An update in place keeps the id and the mark.
    let mut update = b.as_peer(a.transport);
    update.persistent_keepalive = Some(25);
    a.handle.add_or_update_peer(update).await.unwrap();
    assert_eq!(a.peer_of(&b).await, peer);
    a.send(local(b"updated")).await;
    assert_eq!(egress(&mut a).await, (peer, ipv4(IP_A, IP_B, b"updated")));

    // A packet queued for egress before the removal keeps the old id.
    a.send(local(b"before removal")).await;
    a.handle.local_barrier().await.unwrap();
    a.handle.remove_peer(b.public()).await.unwrap();
    a.handle
        .add_or_update_peer(b.as_peer(a.transport))
        .await
        .unwrap();
    let new = a.peer_of(&b).await;
    assert_ne!(new, peer);
    assert!(!a.handle.set_plaintext_egress(peer, true).await.unwrap());
    assert_eq!(
        egress(&mut a).await,
        (peer, ipv4(IP_A, IP_B, b"before removal"))
    );
    // The re-added peer is unmarked: sealed, and nothing reaches the egress under its id.
    a.handle.force_handshake(new, None).await.unwrap();
    eventually(|| async { a.handle.peer_has_session(new).await.unwrap() == Some(true) }).await;
    a.send(local(b"re-added")).await;
    assert_eq!(b.expect_delivery().await.1, ipv4(IP_A, IP_B, b"re-added"));
    assert!(a.egress.as_mut().unwrap().try_recv().is_none());
}

#[tokio::test]
async fn the_add_closed_read_back_mark_open_order_seals_nothing() {
    let (mut a, mut b, _script) = pair(Setup {
        egress: Some(8),
        ..Setup::default()
    })
    .await;
    // `a` drops and re-adds `b` closed, as a consumer adding it for the first time would.
    a.handle.remove_peer(b.public()).await.unwrap();
    let mut closed = b.as_peer(a.transport);
    closed.allowed_ips.clear();
    a.handle.add_or_update_peer(closed).await.unwrap();
    let peer = a.peer_of(&b).await;
    assert!(a.handle.set_plaintext_egress(peer, true).await.unwrap());
    a.handle
        .set_allowed_ips(
            b.public(),
            vec![AllowedIp {
                addr: IP_B.into(),
                cidr: 32,
            }],
        )
        .await
        .unwrap();
    for i in 0..3u8 {
        a.send(local(&[i])).await;
        assert_eq!(egress(&mut a).await, (peer, ipv4(IP_A, IP_B, &[i])));
    }
    // Nothing was sealed, and no handshake started for the data.
    b.expect_no_delivery().await;
    assert_eq!(a.handle.peer_has_session(peer).await.unwrap(), Some(false));
}

#[tokio::test]
async fn a_marked_peer_answers_handshakes_and_its_inbound_traffic_is_delivered() {
    let (mut a, mut b, _script) = pair(Setup {
        egress: Some(8),
        ..Setup::default()
    })
    .await;
    let peer = a.peer_of(&b).await;
    a.handle.set_plaintext_egress(peer, true).await.unwrap();
    let back = b.peer_of(&a).await;
    b.handle.force_handshake(back, None).await.unwrap();
    eventually(|| async { a.handle.peer_has_session(peer).await.unwrap() == Some(true) }).await;
    b.send(PacketBuf::from_packet(&ipv4(IP_B, IP_A, b"inbound")))
        .await;
    assert_eq!(
        a.expect_delivery().await,
        (peer, ipv4(IP_B, IP_A, b"inbound"))
    );
    a.send(local(b"outbound")).await;
    assert_eq!(egress(&mut a).await, (peer, ipv4(IP_A, IP_B, b"outbound")));
    b.expect_no_delivery().await;
}

#[tokio::test]
async fn packets_routed_before_the_mark_stay_sealed() {
    let (a, mut b, script) = connected(Setup {
        egress: Some(8),
        ..Setup::default()
    })
    .await;
    let peer = a.peer_of(&b).await;
    // Routed and sealed, held at the transport, then the mark.
    script.hold();
    a.send(local(b"routed before")).await;
    a.handle.local_barrier().await.unwrap();
    a.handle.set_plaintext_egress(peer, true).await.unwrap();
    script.release();
    assert_eq!(
        b.expect_delivery().await.1,
        ipv4(IP_A, IP_B, b"routed before")
    );
}
