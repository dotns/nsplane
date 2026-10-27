//! Tracked local packets through the engine: `TrackedSender` accepts tagged packets, and the
//! engine reports exactly one `SendResult` per accepted packet: `Sent` once the transport call
//! carrying its datagram succeeded, `NotSent` with the reason at every drop site.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

mod support;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nsplane::{
    DROP_FRAGMENT_OVERSIZE, DROP_NO_TRANSPORT, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
    DROP_TRANSPORT_REMOVED, DROP_TRANSPORT_SEND_ERROR, Ecn, PacketBuf, PacketFilter, Path,
    PathPolicy, PeerId, SendOutcome, SendResult, TrackedRefused, TransportId, reasons,
};
use nsplane_core::{MessageKind, Roam, Verdict};
use support::{
    IP_A, IP_B, IP_NOWHERE, QUIET, Setup, WAIT, connected, eventually, ipv4, ipv4_len, pair,
    results, tag, tagged, wire,
};
use tokio::time::{sleep, timeout};

const fn outcome(result: SendResult) -> (u64, SendOutcome) {
    (result.tag.get(), result.outcome)
}

const fn not_sent(reason: &'static str) -> SendOutcome {
    SendOutcome::NotSent { reason }
}

/// Every call that carried a tracked data message ended with it.
fn tracked_datagrams_end_their_calls(calls: &[Vec<(Option<u64>, bool)>]) {
    for call in calls {
        for (i, (_, tracked)) in call.iter().enumerate() {
            assert!(!tracked || i + 1 == call.len(), "{calls:?}");
        }
    }
}

#[tokio::test]
async fn a_tracked_packet_is_sent_once_its_transport_call_succeeded() {
    for (workers, inline) in [(0, false), (0, true), (2, false)] {
        let (mut a, mut b, script) = connected(Setup {
            workers,
            inline,
            ..Setup::default()
        })
        .await;
        let peer = a.peer_of(&b).await;
        let before = a.handle.peer_stats(peer).await.unwrap().unwrap().data_tx;
        let packet = tagged(IP_B, 7);
        let len = packet.len();
        a.track(packet).await;
        let result = a.result().await;
        assert_eq!(outcome(result), (7, SendOutcome::Sent { peer, bytes: len }));
        assert_eq!(
            b.expect_delivery().await.1,
            ipv4(IP_A, IP_B, &7u64.to_be_bytes())
        );
        let after = a.handle.peer_stats(peer).await.unwrap().unwrap().data_tx;
        assert_eq!(after - before, len as u64);
        // The datagram carried the tag and the marker to the transport.
        assert!(
            script
                .calls()
                .iter()
                .flatten()
                .any(|d| *d == (Some(7), true)),
            "{:?}",
            script.calls()
        );
        a.no_result().await;
    }
}

#[tokio::test]
async fn tracked_datagrams_end_their_transport_calls() {
    for (workers, inline) in [(0, false), (0, true), (2, false)] {
        let (mut a, mut b, script) = connected(Setup {
            workers,
            inline,
            ..Setup::default()
        })
        .await;
        // Hold the transport so untracked and tracked datagrams queue up together.
        script.hold();
        for i in 0..20u64 {
            if i % 5 == 4 {
                a.track(tagged(IP_B, 100 + i)).await;
            } else {
                a.send(PacketBuf::from_packet(&ipv4(IP_A, IP_B, &i.to_be_bytes())))
                    .await;
            }
        }
        sleep(QUIET).await;
        script.release();
        let got = results(&mut a, 4).await;
        assert!(
            got.iter()
                .all(|r| matches!(r.outcome, SendOutcome::Sent { .. }))
        );
        for _ in 0..20 {
            b.expect_delivery().await;
        }
        tracked_datagrams_end_their_calls(&script.calls());
    }
}

#[tokio::test]
async fn a_transport_failure_in_the_middle_of_a_batch_fails_only_its_datagram() {
    for (workers, inline) in [(0, false), (0, true), (2, false)] {
        let (mut a, mut b, script) = connected(Setup {
            workers,
            inline,
            ..Setup::default()
        })
        .await;
        script.fail(3);
        script.hold();
        for i in 1..=5u64 {
            a.send(PacketBuf::from_packet(&ipv4(IP_A, IP_B, b"before")))
                .await;
            a.track(tagged(IP_B, i)).await;
            a.send(PacketBuf::from_packet(&ipv4(IP_A, IP_B, b"after")))
                .await;
        }
        sleep(QUIET).await;
        script.release();
        let got: Vec<_> = results(&mut a, 5).await.into_iter().map(outcome).collect();
        let peer = a.peer_of(&b).await;
        let bytes = tagged(IP_B, 1).len();
        let sent = SendOutcome::Sent { peer, bytes };
        assert_eq!(
            got,
            [
                (1, sent),
                (2, sent),
                (3, not_sent(DROP_TRANSPORT_SEND_ERROR)),
                (4, sent),
                (5, sent),
            ]
        );
        for _ in 0..14 {
            b.expect_delivery().await;
        }
        b.expect_no_delivery().await;
        tracked_datagrams_end_their_calls(&script.calls());
        assert_eq!(a.drops(DROP_TRANSPORT_SEND_ERROR).await, 1);
    }
}

#[tokio::test]
async fn the_tracked_sender_needs_a_tag_and_refuses_an_outstanding_one() {
    let (mut a, b, script) = connected(Setup::default()).await;
    let sender = a.tracked.clone().unwrap();
    let untagged = PacketBuf::from_packet(&ipv4(IP_A, IP_B, b"untagged"));
    let refused = sender.send(untagged).await.unwrap_err();
    assert!(matches!(refused, TrackedRefused::Untagged(_)));
    assert!(!refused.into_packet().is_tracked());

    script.hold();
    sender.send(tagged(IP_B, 1)).await.unwrap();
    let refused = sender.try_send(tagged(IP_B, 1)).unwrap_err();
    assert!(matches!(refused, TrackedRefused::Duplicate(_)));
    script.release();
    let peer = a.peer_of(&b).await;
    assert!(matches!(
        a.result().await.outcome,
        SendOutcome::Sent { peer: p, .. } if p == peer
    ));
    // Once its result is out, the tag may be used again.
    sender.send(tagged(IP_B, 1)).await.unwrap();
    assert_eq!(a.result().await.tag, tag(1));
}

#[tokio::test]
async fn outstanding_results_are_bounded_by_the_capacity() {
    let (mut a, _b, script) = connected(Setup {
        tracked: Some(2),
        ..Setup::default()
    })
    .await;
    let sender = a.tracked.clone().unwrap();
    script.hold();
    sender.try_send(tagged(IP_B, 1)).unwrap();
    sender.try_send(tagged(IP_B, 2)).unwrap();
    assert!(matches!(
        sender.try_send(tagged(IP_B, 3)),
        Err(TrackedRefused::Full(_))
    ));
    // `send` waits until a result is received.
    let waiting = tokio::spawn({
        let sender = sender.clone();
        async move { sender.send(tagged(IP_B, 3)).await }
    });
    script.release();
    sleep(QUIET).await;
    assert!(!waiting.is_finished());
    assert_eq!(a.result().await.tag, tag(1));
    timeout(WAIT, waiting).await.unwrap().unwrap().unwrap();
    assert_eq!(a.result().await.tag, tag(2));
    assert_eq!(a.result().await.tag, tag(3));
}

/// Drops the packets to `drop` and handles those to `handle`.
#[derive(Debug)]
struct Outbound {
    drop: Ipv4Addr,
    handle: Ipv4Addr,
}

impl PacketFilter for Outbound {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet.as_packet()[16..20]).unwrap());
        if dst == self.drop {
            Verdict::Drop {
                reason: "test drop",
            }
        } else if dst == self.handle {
            Verdict::Handled
        } else {
            Verdict::Accept
        }
    }
}

#[tokio::test]
async fn no_route_filter_drops_and_handled_packets_are_not_sent() {
    for workers in [0, 2] {
        let (mut a, b, _script) = connected(Setup {
            workers,
            filters: vec![Box::new(Outbound {
                drop: IP_B,
                handle: Ipv4Addr::new(10, 0, 0, 3),
            })],
            ..Setup::default()
        })
        .await;
        a.handle
            .set_allowed_ips(
                b.public(),
                vec![
                    nsplane::AllowedIp {
                        addr: IP_B.into(),
                        cidr: 32,
                    },
                    nsplane::AllowedIp {
                        addr: Ipv4Addr::new(10, 0, 0, 3).into(),
                        cidr: 32,
                    },
                ],
            )
            .await
            .unwrap();
        a.track(tagged(IP_NOWHERE, 1)).await;
        a.track(tagged(IP_B, 2)).await;
        a.track(tagged(Ipv4Addr::new(10, 0, 0, 3), 3)).await;
        let got: Vec<_> = results(&mut a, 3).await.into_iter().map(outcome).collect();
        assert_eq!(
            got,
            [
                (1, not_sent(reasons::NO_ROUTE)),
                (2, not_sent("test drop")),
                (3, not_sent(reasons::FILTER_HANDLED)),
            ]
        );
        a.no_result().await;
    }
}

#[tokio::test]
async fn without_a_session_a_tracked_packet_is_not_sent_and_the_handshake_starts() {
    for workers in [0, 2] {
        let (mut a, mut b, _script) = pair(Setup {
            workers,
            ..Setup::default()
        })
        .await;
        let peer = a.peer_of(&b).await;
        a.track(tagged(IP_B, 1)).await;
        assert_eq!(
            outcome(a.result().await),
            (1, not_sent(reasons::NO_SESSION))
        );
        // The handshake started as for an untracked packet; the packet itself never goes.
        eventually(|| async { a.handle.peer_has_session(peer).await.unwrap() == Some(true) }).await;
        b.expect_no_delivery().await;
        // A retry once the session is up is sent.
        a.track(tagged(IP_B, 1)).await;
        assert!(matches!(a.result().await.outcome, SendOutcome::Sent { .. }));
        assert_eq!(
            b.expect_delivery().await.1,
            ipv4(IP_A, IP_B, &1u64.to_be_bytes())
        );
    }
}

/// A tracked packet of `len` bytes to `b`, DF set with `df`.
fn big(value: u64, len: usize, df: bool) -> PacketBuf {
    let mut packet = PacketBuf::from_packet(&ipv4_len(IP_A, IP_B, len, df));
    packet.set_tag(Some(tag(value)));
    packet
}

#[tokio::test]
async fn above_the_mtu_with_a_fragmenter_a_tracked_packet_is_not_sent() {
    let (mut a, mut b, _script) = connected(Setup {
        fragmenter: true,
        ..Setup::default()
    })
    .await;
    // One it would split, and a DF one it answers with an ICMP error.
    a.track(big(1, 1500, false)).await;
    a.track(big(2, 1500, true)).await;
    let got: Vec<_> = results(&mut a, 2).await.into_iter().map(outcome).collect();
    assert_eq!(
        got,
        [
            (1, not_sent(DROP_FRAGMENT_OVERSIZE)),
            (2, not_sent(DROP_FRAGMENT_OVERSIZE)),
        ]
    );
    b.expect_no_delivery().await;
    // The ICMP error about the DF packet reached the local side.
    let (_, icmp) = a.expect_delivery().await;
    assert_eq!(icmp[9], 1);
    // An untracked packet of the same size is split.
    a.send(PacketBuf::from_packet(&ipv4_len(IP_A, IP_B, 1500, false)))
        .await;
    b.expect_delivery().await;
    b.expect_delivery().await;
    let stats = a.handle.fragment_stats().await.unwrap();
    assert_eq!(stats.fragmented, 1);
    a.no_result().await;
}

#[tokio::test]
async fn above_the_mtu_without_a_fragmenter_a_tracked_packet_is_sealed_and_sent() {
    let (mut a, mut b, _script) = connected(Setup::default()).await;
    let peer = a.peer_of(&b).await;
    a.track(big(1, 1500, false)).await;
    assert_eq!(
        outcome(a.result().await),
        (1, SendOutcome::Sent { peer, bytes: 1500 })
    );
    assert_eq!(b.expect_delivery().await.1.len(), 1500);
}

/// Selects `b`'s path for handshakes only and never adopts one.
#[derive(Debug)]
struct HandshakesOnly;

impl PathPolicy for HandshakesOnly {
    fn select(&self, _peer: PeerId, kind: MessageKind) -> Option<Path> {
        (kind != MessageKind::Data).then_some(Path {
            transport: TransportId::new(1),
            addr: support::addr(2),
            ecn: Ecn::NotEct,
        })
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
    }
}

#[tokio::test]
async fn a_peer_without_a_path_for_data_is_no_path() {
    let (mut a, b, _script) = pair(Setup {
        policy: Some(Box::new(HandshakesOnly)),
        ..Setup::default()
    })
    .await;
    // Re-added without a path.
    a.handle.remove_peer(b.public()).await.unwrap();
    let mut config = b.as_peer(a.transport);
    config.path = None;
    a.handle.add_or_update_peer(config).await.unwrap();
    let peer = a.peer_of(&b).await;
    a.handle.force_handshake(peer, None).await.unwrap();
    eventually(|| async { a.handle.peer_has_session(peer).await.unwrap() == Some(true) }).await;
    a.track(tagged(IP_B, 1)).await;
    assert_eq!(outcome(a.result().await), (1, not_sent(reasons::NO_PATH)));
}

#[tokio::test]
async fn a_path_to_no_installed_transport_is_no_transport() {
    let (mut a, b, _script) = connected(Setup::default()).await;
    a.handle
        .set_path(
            b.public(),
            Path {
                transport: TransportId::new(9),
                addr: support::addr(2),
                ecn: Ecn::NotEct,
            },
        )
        .await
        .unwrap();
    a.track(tagged(IP_B, 1)).await;
    assert_eq!(outcome(a.result().await), (1, not_sent(DROP_NO_TRANSPORT)));
}

#[tokio::test]
async fn a_closing_transport_fails_the_datagram_of_its_call_and_closes_the_rest() {
    for inline in [false, true] {
        let (mut a, _b, script) = connected(Setup {
            inline,
            ..Setup::default()
        })
        .await;
        script.close_on(2);
        script.hold();
        for i in 1..=4 {
            a.track(tagged(IP_B, i)).await;
        }
        sleep(QUIET).await;
        script.release();
        let got: Vec<_> = results(&mut a, 4).await.into_iter().map(outcome).collect();
        assert!(matches!(got[0], (1, SendOutcome::Sent { .. })), "{got:?}");
        assert_eq!(got[1], (2, not_sent(DROP_TRANSPORT_SEND_ERROR)));
        assert_eq!(
            &got[2..],
            [
                (3, not_sent(DROP_TRANSPORT_CLOSED)),
                (4, not_sent(DROP_TRANSPORT_CLOSED)),
            ]
        );
        // Later packets find the transport closed.
        a.track(tagged(IP_B, 5)).await;
        assert_eq!(
            outcome(a.result().await),
            (5, not_sent(DROP_TRANSPORT_CLOSED))
        );
    }
}

#[tokio::test]
async fn a_removed_transport_reports_its_queued_tracked_datagrams() {
    let (mut a, _b, script) = connected(Setup::default()).await;
    script.hold();
    for i in 1..=3 {
        a.track(tagged(IP_B, i)).await;
    }
    sleep(QUIET).await;
    a.handle
        .remove_transport(TransportId::new(1))
        .await
        .unwrap();
    let got: Vec<_> = results(&mut a, 3).await.into_iter().map(outcome).collect();
    // The first was in the call the stop cancelled: not handed off.
    assert_eq!(
        got,
        [
            (1, not_sent(DROP_TRANSPORT_REMOVED)),
            (2, not_sent(DROP_TRANSPORT_REMOVED)),
            (3, not_sent(DROP_TRANSPORT_REMOVED)),
        ]
    );
}

#[tokio::test]
async fn a_replaced_transport_sends_the_queued_tracked_datagrams() {
    let (mut a, mut b, script) = connected(Setup::default()).await;
    script.hold();
    for i in 1..=3 {
        a.track(tagged(IP_B, i)).await;
    }
    sleep(QUIET).await;
    // The new end reaches `b` like the old one; `b` keeps its end.
    let (new_a, _new_b, _) = wire(false);
    a.handle.replace_transport(new_a).await.unwrap();
    // The new link goes nowhere `b` reads, but the calls succeed: sent.
    let got: Vec<_> = results(&mut a, 3).await.into_iter().map(outcome).collect();
    assert!(
        got.iter()
            .all(|(_, o)| matches!(o, SendOutcome::Sent { .. })),
        "{got:?}"
    );
    b.expect_no_delivery().await;
}

#[tokio::test]
async fn a_full_transmit_backlog_is_transmit_full() {
    // Two transports: the one to `b` stalls, the other keeps local reads going.
    let (wa, wb, script) = wire(false);
    let (second, _far, _) = support::wire_ids(TransportId::new(3), TransportId::new(4), false);
    let mut a = support::node_on(
        1,
        IP_A,
        wa,
        Setup {
            queue_capacity: 2,
            ..Setup::default()
        },
    );
    a.handle.add_transport(second).await.unwrap();
    let b = support::node_on(
        2,
        IP_B,
        wb,
        Setup {
            tracked: None,
            ..Setup::default()
        },
    );
    a.handle
        .add_or_update_peer(b.as_peer(TransportId::new(1)))
        .await
        .unwrap();
    b.handle
        .add_or_update_peer(a.as_peer(TransportId::new(2)))
        .await
        .unwrap();
    let peer = a.peer_of(&b).await;
    a.handle.force_handshake(peer, None).await.unwrap();
    eventually(|| async { a.handle.peer_has_session(peer).await.unwrap() == Some(true) }).await;
    script.hold();
    for i in 1..=10 {
        a.track(tagged(IP_B, i)).await;
    }
    let mut full = 0;
    let mut got = Vec::new();
    for _ in 0..10 {
        if let Ok(Some(result)) = timeout(QUIET, a.results.as_mut().unwrap().recv()).await {
            if result.outcome == not_sent(DROP_TRANSMIT_FULL) {
                full += 1;
            }
            got.push(result.tag.get());
        }
    }
    assert!(full > 0, "{got:?}");
    assert_eq!(a.drops(DROP_TRANSMIT_FULL).await, full);
    script.release();
    let rest = results(&mut a, 10 - got.len()).await;
    assert!(
        rest.iter()
            .all(|r| matches!(r.outcome, SendOutcome::Sent { .. }))
    );
}

#[tokio::test]
async fn stopping_the_engine_reports_the_outstanding_packets() {
    let (mut a, _b, script) = connected(Setup::default()).await;
    script.hold();
    for i in 1..=3 {
        a.track(tagged(IP_B, i)).await;
    }
    sleep(QUIET).await;
    a.handle.shutdown().await.unwrap();
    let mut got: Vec<_> = results(&mut a, 3).await.into_iter().map(outcome).collect();
    got.sort_by_key(|(t, _)| *t);
    assert_eq!(
        got,
        [
            (1, not_sent(reasons::ENGINE_STOPPED)),
            (2, not_sent(reasons::ENGINE_STOPPED)),
            (3, not_sent(reasons::ENGINE_STOPPED)),
        ]
    );
    let results = a.results.as_mut().unwrap();
    assert_eq!(timeout(WAIT, results.recv()).await.unwrap(), None);
    let refused = a.tracked.as_ref().unwrap().send(tagged(IP_B, 4)).await;
    assert!(matches!(refused, Err(TrackedRefused::Stopped(_))));
}

#[tokio::test]
async fn dropping_the_engine_reports_the_outstanding_packets() {
    let (mut a, _b, script) = connected(Setup::default()).await;
    script.hold();
    a.track(tagged(IP_B, 1)).await;
    sleep(QUIET).await;
    drop(a.engine.take());
    assert_eq!(
        outcome(a.result().await),
        (1, not_sent(reasons::ENGINE_STOPPED))
    );
    let results = a.results.as_mut().unwrap();
    assert_eq!(timeout(WAIT, results.recv()).await.unwrap(), None);
}

#[tokio::test]
async fn a_tracked_packet_to_a_plaintext_egress_peer_is_handed_out_untracked() {
    let (mut a, b, _script) = connected(Setup {
        egress: Some(4),
        ..Setup::default()
    })
    .await;
    let peer = a.peer_of(&b).await;
    assert!(a.handle.set_plaintext_egress(peer, true).await.unwrap());
    a.track(tagged(IP_B, 1)).await;
    assert_eq!(
        outcome(a.result().await),
        (1, not_sent(reasons::PLAINTEXT_EGRESS))
    );
    let egress = a.egress.as_mut().unwrap();
    let (to, packet) = timeout(WAIT, egress.recv()).await.unwrap().unwrap();
    assert_eq!(to, peer);
    assert_eq!(packet.tag(), Some(tag(1)));
    assert!(!packet.is_tracked());
}

#[tokio::test]
async fn a_clone_of_a_tracked_packet_is_untracked() {
    let (mut a, mut b, _script) = connected(Setup::default()).await;
    let mut original = tagged(IP_B, 1);
    original.set_tracked(true);
    let clone = original.clone();
    assert_eq!((clone.tag(), clone.is_tracked()), (Some(tag(1)), false));
    // A marked packet from the source is untracked too.
    a.send(clone).await;
    a.send(original).await;
    b.expect_delivery().await;
    b.expect_delivery().await;
    a.no_result().await;
}

/// Records the tags of the local packets it sees.
#[derive(Debug, Default)]
struct Seen(Mutex<Vec<Option<u64>>>);

#[derive(Debug)]
struct Recording(Arc<Seen>);

impl PacketFilter for Recording {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let seen = packet.tag().map(std::num::NonZeroU64::get);
        self.0.0.lock().unwrap().push(seen);
        Verdict::Accept
    }
}

#[tokio::test]
async fn the_local_barrier_waits_for_the_packets_the_tracked_sender_accepted() {
    for workers in [0, 2] {
        let seen = Arc::new(Seen::default());
        let (mut a, _b, _script) = connected(Setup {
            workers,
            filters: vec![Box::new(Recording(Arc::clone(&seen)))],
            ..Setup::default()
        })
        .await;
        // Suspended, the engine takes nothing: the accepted packet waits in its queue.
        a.handle.suspend().await.unwrap();
        a.track(tagged(IP_B, 1)).await;
        let handle = a.handle.clone();
        let barrier = tokio::spawn(async move { handle.local_barrier().await });
        sleep(QUIET).await;
        assert!(!barrier.is_finished());
        a.handle.resume().await.unwrap();
        timeout(WAIT, barrier).await.unwrap().unwrap().unwrap();
        // The barrier passed after the filter saw the packet.
        assert!(seen.0.lock().unwrap().contains(&Some(1)));
        a.result().await;
        // A barrier with nothing accepted since passes at once.
        timeout(WAIT, a.handle.local_barrier())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn results_follow_the_engine_after_a_second_sender_replaces_the_first() {
    let (wa, _wb, _script) = wire(false);
    let (source, _local, _mtu) = nsplane::ChannelSource::new(4, 1420);
    let (sink, _delivered) = nsplane::ChannelSink::new(4);
    let builder = nsplane::EngineBuilder::new(source, sink).transport(wa);
    let (builder, first, mut first_results) = builder.tracked_sender(4);
    let (builder, second, _second_results) = builder.tracked_sender(4);
    let _engine = builder.build().unwrap();
    assert!(matches!(
        first.send(tagged(IP_B, 1)).await,
        Err(TrackedRefused::Stopped(_))
    ));
    assert_eq!(first_results.recv().await, None);
    second.send(tagged(IP_B, 1)).await.unwrap();
}
