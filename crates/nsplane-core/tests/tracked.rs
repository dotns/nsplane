//! Tracked local packets through the core: exactly one `Output::Tracked` per tracked packet,
//! `Sealed` right before the datagram that carries it, `NotSent` with the reason at every drop
//! site of the send path.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use common::{Net, Tracked, ip4, packet_buf, udp4};
use nsplane_core::{
    ConfigChange, CoreConfig, Event, Input, MessageKind, PacketBuf, PacketFilter, Path, PathPolicy,
    PeerId, Roam, TrackedOutcome, Verdict, reasons,
};

const fn tag(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

/// A tracked local packet from core 0 to core `to` carrying `payload`.
fn tracked(value: u64, to: usize, payload: &[u8]) -> PacketBuf {
    let mut packet = packet_buf(&udp4(ip4(0), ip4(to), payload));
    packet.set_tag(Some(tag(value)));
    packet.set_tracked(true);
    packet
}

/// What the outbound filter does with each packet.
#[derive(Debug, Clone, Copy, Default)]
enum Mode {
    #[default]
    Accept,
    Drop,
    Handled,
    /// Changes the tag and clears the marker, then accepts.
    Rewrite,
}

#[derive(Debug, Default)]
struct Outbound {
    mode: Mutex<Mode>,
    seen: Mutex<Vec<(Option<NonZeroU64>, bool)>>,
}

#[derive(Debug)]
struct Installed(Arc<Outbound>);

impl PacketFilter for Installed {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0
            .seen
            .lock()
            .unwrap()
            .push((packet.tag(), packet.is_tracked()));
        let mode = *self.0.mode.lock().unwrap();
        match mode {
            Mode::Accept => Verdict::Accept,
            Mode::Drop => Verdict::Drop {
                reason: "test drop",
            },
            Mode::Handled => Verdict::Handled,
            Mode::Rewrite => {
                packet.set_tag(Some(tag(999)));
                packet.set_tracked(false);
                Verdict::Accept
            }
        }
    }
}

/// Two cores, crypto jobs on core 0 with `crypto_jobs`, an [`Outbound`] filter on core 0.
fn net(filter: &Arc<Outbound>, crypto_jobs: bool) -> Net {
    let mut net = Net::with_configs(2, |i| CoreConfig {
        filters: if i == 0 {
            vec![Box::new(Installed(Arc::clone(filter)))]
        } else {
            Vec::new()
        },
        crypto_jobs: crypto_jobs && i == 0,
        ..CoreConfig::default()
    });
    net.clear_logs();
    net
}

/// Feeds `packet` to core 0 as a local packet, through a crypto job with `crypto_jobs`.
fn send(net: &mut Net, packet: PacketBuf, crypto_jobs: bool) {
    let input = Input::Local { packet };
    if crypto_jobs {
        if let Some(mut job) = net.cores[0].handle_input_deferred(input, net.now) {
            job.run();
            net.cores[0].complete_job(job);
        }
    } else {
        net.cores[0].handle_input(input, net.now);
    }
}

const fn not_sent(value: u64, peer: Option<PeerId>, reason: &'static str) -> Tracked {
    Tracked {
        tag: tag(value),
        peer,
        outcome: TrackedOutcome::NotSent { reason },
        transmitted: 0,
    }
}

/// Core 0's tracked log without the transmit positions.
fn outcomes(net: &Net) -> Vec<Tracked> {
    net.tracked[0]
        .iter()
        .map(|t| Tracked {
            transmitted: 0,
            ..*t
        })
        .collect()
}

#[test]
fn a_sealed_tracked_packet_reports_its_peer_and_plaintext_length_before_its_datagram() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        let peer = net.peer_id(0, 1);
        let before = net.cores[0].peer_stats(peer).unwrap().data_tx;

        // An untracked packet first, so the datagram's position is not trivially 0.
        send(
            &mut net,
            packet_buf(&udp4(ip4(0), ip4(1), b"plain")),
            crypto_jobs,
        );
        let packet = tracked(7, 1, b"tracked payload");
        let len = packet.len();
        send(&mut net, packet, crypto_jobs);
        let in_flight = net.drain();

        assert_eq!(
            net.tracked[0],
            [Tracked {
                tag: tag(7),
                peer: Some(peer),
                outcome: TrackedOutcome::Sealed { bytes: len },
                transmitted: 1,
            }]
        );
        // The datagram right after it carries the tag and the marker.
        let datagram = &in_flight[1].data;
        assert_eq!(datagram.as_packet()[0], 4);
        assert_eq!(datagram.tag(), Some(tag(7)));
        assert!(datagram.is_tracked());
        assert!(!in_flight[0].data.is_tracked());
        // `bytes` is what data_tx counts.
        let plain = udp4(ip4(0), ip4(1), b"plain").len();
        assert_eq!(
            net.cores[0].peer_stats(peer).unwrap().data_tx - before,
            (plain + len) as u64
        );
    }
}

#[test]
fn a_packet_without_headroom_yields_one_result_through_the_copy() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        let bytes = udp4(ip4(0), ip4(1), b"shared");
        let mut whole = PacketBuf::with_capacity(bytes.len()).into_bytes();
        whole.extend_from_slice(&bytes);
        let mut packet = PacketBuf::from_shared(whole, 0, bytes.len()).unwrap();
        packet.set_tag(Some(tag(3)));
        packet.set_tracked(true);
        send(&mut net, packet, crypto_jobs);
        net.pump();
        assert_eq!(
            outcomes(&net),
            [Tracked {
                tag: tag(3),
                peer: Some(net.peer_id(0, 1)),
                outcome: TrackedOutcome::Sealed { bytes: bytes.len() },
                transmitted: 0,
            }]
        );
    }
}

#[test]
fn only_marked_and_tagged_packets_are_tracked() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        let mut marked = packet_buf(&udp4(ip4(0), ip4(1), b"marked"));
        marked.set_tracked(true);
        let mut tagged = packet_buf(&udp4(ip4(0), ip4(1), b"tagged"));
        tagged.set_tag(Some(tag(1)));
        send(&mut net, marked, crypto_jobs);
        send(&mut net, tagged, crypto_jobs);
        net.pump();
        assert_eq!(net.tracked[0], []);
        assert_eq!(net.take_delivered(1).len(), 2);
    }
}

#[test]
fn a_filter_cannot_change_the_tag_or_the_marker_of_a_tracked_packet() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        *filter.mode.lock().unwrap() = Mode::Rewrite;
        send(&mut net, tracked(4, 1, b"rewritten"), crypto_jobs);
        let in_flight = net.drain();
        assert_eq!(*filter.seen.lock().unwrap(), [(Some(tag(4)), true)]);
        assert_eq!(net.tracked[0].len(), 1);
        assert_eq!(net.tracked[0][0].tag, tag(4));
        assert!(matches!(
            net.tracked[0][0].outcome,
            TrackedOutcome::Sealed { .. }
        ));
        assert_eq!(in_flight[0].data.tag(), Some(tag(4)));
        assert!(in_flight[0].data.is_tracked());
    }
}

#[test]
fn no_route_filter_drops_and_handled_packets_are_not_sent() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        let peer = net.peer_id(0, 1);

        // To core 2's address: routed to no peer.
        send(&mut net, tracked(1, 2, b"no route"), crypto_jobs);
        *filter.mode.lock().unwrap() = Mode::Drop;
        send(&mut net, tracked(2, 1, b"dropped"), crypto_jobs);
        *filter.mode.lock().unwrap() = Mode::Handled;
        send(&mut net, tracked(3, 1, b"handled"), crypto_jobs);
        net.pump();

        assert_eq!(
            outcomes(&net),
            [
                not_sent(1, None, reasons::NO_ROUTE),
                not_sent(2, Some(peer), "test drop"),
                not_sent(3, Some(peer), reasons::FILTER_HANDLED),
            ]
        );
        // The drops count as for untracked packets; a handled packet is not a drop.
        let drops: Vec<_> = net
            .take_events(0)
            .into_iter()
            .filter_map(|e| match e {
                Event::Dropped { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(drops, [reasons::NO_ROUTE, "test drop"]);
        assert_eq!(net.take_delivered(1), []);
    }
}

#[test]
fn without_a_session_a_tracked_packet_is_not_sent_and_the_handshake_starts() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        let peer = net.peer_id(0, 1);
        send(&mut net, tracked(9, 1, b"no session"), crypto_jobs);
        // Reported at once, before any datagram moved.
        let in_flight = net.drain();
        assert_eq!(
            outcomes(&net),
            [not_sent(9, Some(peer), reasons::NO_SESSION)]
        );
        assert!(net.events[0].contains(&Event::Dropped {
            peer: Some(peer),
            reason: reasons::NO_SESSION,
        }));
        // The handshake starts, in a datagram with neither the tag nor the marker.
        let [initiation] = &in_flight[..] else {
            panic!("{in_flight:?}");
        };
        assert_eq!(initiation.data.as_packet()[0], 1);
        assert_eq!(initiation.data.tag(), None);
        assert!(!initiation.data.is_tracked());
        for datagram in in_flight {
            net.receive(1, datagram.arrival, datagram.data);
        }
        net.pump();
        // The session came up, and the packet was never queued, so it is never sent.
        assert_eq!(net.cores[0].peer_has_session(peer), Some(true));
        assert_eq!(net.take_delivered(1), []);
        assert_eq!(net.tracked[0].len(), 1);
    }
}

#[test]
fn without_a_session_a_handshake_in_progress_is_not_restarted() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, false);
    let peer = net.peer_id(0, 1);
    // An untracked packet queues and starts the handshake.
    send(
        &mut net,
        packet_buf(&udp4(ip4(0), ip4(1), b"queued")),
        false,
    );
    let first = net.drain();
    assert_eq!(first.len(), 1);
    send(&mut net, tracked(2, 1, b"tracked"), false);
    // No second initiation while one is in flight.
    assert_eq!(net.drain().len(), 0);
    assert_eq!(
        outcomes(&net),
        [not_sent(2, Some(peer), reasons::NO_SESSION)]
    );
}

/// Selects core 1's path for handshakes only and never adopts one, so a peer configured
/// without a path has a session but no path for data.
#[derive(Debug)]
struct HandshakesOnly(Path);

impl PathPolicy for HandshakesOnly {
    fn select(&self, _peer: PeerId, kind: MessageKind) -> Option<Path> {
        (kind != MessageKind::Data).then_some(self.0)
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
    }
}

#[test]
fn a_peer_without_a_path_for_data_is_no_path() {
    for crypto_jobs in [false, true] {
        let mut net = Net::unpeered(2, |i| CoreConfig {
            policy: if i == 0 {
                Box::new(HandshakesOnly(common::path(1)))
            } else {
                Box::new(nsplane_core::StandardRoaming)
            },
            crypto_jobs: crypto_jobs && i == 0,
            ..CoreConfig::default()
        });
        let mut config = net.peer_config(1);
        config.path = None;
        net.configure(0, ConfigChange::AddOrUpdatePeer(config));
        net.add_peer(1, 0);
        let peer = net.peer_id(0, 1);
        net.handshake(0, 1);
        assert_eq!(net.cores[0].peer_has_session(peer), Some(true));
        assert_eq!(net.cores[0].data_path(peer), None);
        net.clear_logs();

        send(&mut net, tracked(4, 1, b"no path"), crypto_jobs);
        net.drain();
        assert_eq!(outcomes(&net), [not_sent(4, Some(peer), reasons::NO_PATH)]);
        assert!(net.events[0].contains(&Event::Dropped {
            peer: Some(peer),
            reason: reasons::NO_PATH,
        }));
    }
}

#[test]
fn a_tracked_packet_to_a_plaintext_egress_peer_is_handed_out_untracked() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        let peer = net.peer_id(0, 1);
        assert!(net.cores[0].set_plaintext_egress(peer, true));
        send(&mut net, tracked(6, 1, b"plain"), crypto_jobs);
        net.pump();
        assert_eq!(
            outcomes(&net),
            [not_sent(6, Some(peer), reasons::PLAINTEXT_EGRESS)]
        );
        let [(to, packet)] = &net.plaintext[0][..] else {
            panic!("{:?}", net.plaintext[0]);
        };
        assert_eq!(*to, peer);
        assert_eq!(packet.tag(), Some(tag(6)));
        assert!(!packet.is_tracked());
        // Not a drop, and no handshake.
        assert!(
            !net.take_events(0)
                .iter()
                .any(|e| matches!(e, Event::Dropped { .. }))
        );
        assert_eq!(net.transmits[0], []);
    }
}

#[test]
fn a_tracked_packet_sealed_in_a_replaced_session_is_an_encapsulate_error() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, true);
    net.handshake(0, 1);
    net.clear_logs();
    let peer = net.peer_id(0, 1);
    let mut job = net.cores[0]
        .handle_input_deferred(
            Input::Local {
                packet: tracked(8, 1, b"stale"),
            },
            net.now,
        )
        .unwrap();
    job.run();
    // A new private key clears the session the job was sealed in.
    let key = nsplane_core::x25519::StaticSecret::from([42; 32]);
    net.configure(0, ConfigChange::SetPrivateKey(key));
    net.clear_logs();
    net.cores[0].complete_job(job);
    net.drain();
    assert_eq!(
        outcomes(&net),
        [not_sent(8, Some(peer), reasons::ENCAPSULATE_ERROR)]
    );
    assert!(net.events[0].contains(&Event::Dropped {
        peer: Some(peer),
        reason: reasons::ENCAPSULATE_ERROR,
    }));
}

#[test]
fn a_tracked_job_whose_peer_was_removed_is_not_sent() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, true);
    net.handshake(0, 1);
    net.clear_logs();
    let peer = net.peer_id(0, 1);
    let job = net.cores[0]
        .handle_input_deferred(
            Input::Local {
                packet: tracked(5, 1, b"orphan"),
            },
            net.now,
        )
        .unwrap();
    net.configure(0, ConfigChange::RemovePeer(net.public_key(1)));
    net.cores[0].complete_job(job);
    net.drain();
    assert_eq!(outcomes(&net), [not_sent(5, Some(peer), reasons::NO_ROUTE)]);
}
