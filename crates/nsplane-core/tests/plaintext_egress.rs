//! Plaintext egress: local packets routed to a marked peer leave after the outbound filters as
//! `Output::Plaintext` instead of being sealed; the mark follows the `PeerId`.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Net, ip4, packet_buf, udp4};
use nsplane_core::{
    AllowedIp, ConfigChange, CoreConfig, Event, Input, PacketBuf, PacketFilter, PeerId, Verdict,
};

/// Records the destinations of the local packets it sees; drops those to `drop`.
#[derive(Debug, Default)]
struct Outbound {
    seen: Mutex<Vec<PeerId>>,
    drop: Mutex<Option<PeerId>>,
}

#[derive(Debug)]
struct Installed(Arc<Outbound>);

impl PacketFilter for Installed {
    fn inbound(&self, _peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        Verdict::Accept
    }

    fn outbound(&self, peer: PeerId, _packet: &mut PacketBuf) -> Verdict {
        self.0.seen.lock().unwrap().push(peer);
        if *self.0.drop.lock().unwrap() == Some(peer) {
            return Verdict::Drop {
                reason: "test drop",
            };
        }
        Verdict::Accept
    }
}

/// Two cores, crypto jobs on core 0 with `crypto_jobs`, an [`Outbound`] filter on core 0.
fn net(filter: &Arc<Outbound>, crypto_jobs: bool) -> Net {
    Net::with_configs(2, |i| CoreConfig {
        filters: if i == 0 {
            vec![Box::new(Installed(Arc::clone(filter)))]
        } else {
            Vec::new()
        },
        crypto_jobs: crypto_jobs && i == 0,
        ..CoreConfig::default()
    })
}

/// Feeds a local packet from core 0 to core 1, through a crypto job with `crypto_jobs`.
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

/// A local packet from core 0 to core 1 carrying `payload`.
fn local(payload: &[u8]) -> PacketBuf {
    packet_buf(&udp4(ip4(0), ip4(1), payload))
}

/// The handshake initiations (type 1) and data messages (type 4) core 0 transmitted.
fn sent_kinds(net: &Net) -> Vec<u8> {
    net.transmits[0].iter().map(|sent| sent.data[0]).collect()
}

#[test]
fn a_marked_peer_gets_its_routed_local_packets_after_the_filters_as_plaintext() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        let peer = net.peer_id(0, 1);
        assert!(net.cores[0].set_plaintext_egress(peer, true));
        let data_tx = net.cores[0].peer_stats(peer).unwrap().data_tx;

        let mut packet = local(b"plain");
        let bytes = packet.as_packet().to_vec();
        packet.set_tag(NonZeroU64::new(5));
        send(&mut net, packet, crypto_jobs);
        net.pump();

        // Not sealed: no datagram, nothing at core 1, nothing counted as sent data.
        assert_eq!(sent_kinds(&net), [0_u8; 0]);
        assert_eq!(net.take_delivered(1), []);
        assert_eq!(net.cores[0].peer_stats(peer).unwrap().data_tx, data_tx);
        // The filters ran, and the packet left as it was, tag kept, marker cleared.
        assert_eq!(*filter.seen.lock().unwrap(), [peer]);
        let [(to, packet)] = &net.plaintext[0][..] else {
            panic!("{:?}", net.plaintext[0]);
        };
        assert_eq!(*to, peer);
        assert_eq!(packet.as_packet(), bytes);
        assert_eq!(packet.tag(), NonZeroU64::new(5));
        assert!(!packet.is_tracked());

        // A filter's drop still drops.
        *filter.drop.lock().unwrap() = Some(peer);
        send(&mut net, local(b"dropped"), crypto_jobs);
        net.pump();
        assert_eq!(net.plaintext[0].len(), 1);
        assert!(net.take_events(0).contains(&Event::Dropped {
            peer: Some(peer),
            reason: "test drop",
        }));
    }
}

#[test]
fn the_mark_applies_to_packets_routed_after_it_and_reverts_with_the_call() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        net.handshake(0, 1);
        net.clear_logs();
        let peer = net.peer_id(0, 1);

        send(&mut net, local(b"before"), crypto_jobs);
        net.pump();
        assert!(net.cores[0].set_plaintext_egress(peer, true));
        send(&mut net, local(b"marked"), crypto_jobs);
        net.pump();
        assert!(net.cores[0].set_plaintext_egress(peer, false));
        send(&mut net, local(b"after"), crypto_jobs);
        net.pump();

        // A packet routed before the mark and after its removal is sealed; the marked one is
        // plaintext.
        let delivered: Vec<_> = net.take_delivered(1).into_iter().map(|(_, p)| p).collect();
        assert_eq!(
            delivered,
            [
                udp4(ip4(0), ip4(1), b"before"),
                udp4(ip4(0), ip4(1), b"after")
            ]
        );
        let plain: Vec<_> = net.plaintext[0]
            .iter()
            .map(|(to, p)| (*to, p.as_packet().to_vec()))
            .collect();
        assert_eq!(plain, [(peer, udp4(ip4(0), ip4(1), b"marked"))]);
    }
}

#[test]
fn packets_queued_in_the_tunnel_before_the_mark_stay_sealed() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, false);
    let peer = net.peer_id(0, 1);
    // No session: the packet is queued in the tunnel behind the handshake it starts.
    let initiation = net.cores[0].poll_output();
    assert!(initiation.is_none());
    send(&mut net, local(b"queued"), false);
    assert!(net.cores[0].set_plaintext_egress(peer, true));
    net.pump();

    // The queued packet goes out sealed once the session is up.
    let delivered: Vec<_> = net.take_delivered(1).into_iter().map(|(_, p)| p).collect();
    assert_eq!(delivered, [udp4(ip4(0), ip4(1), b"queued")]);
    assert_eq!(net.plaintext[0].len(), 0);
    // The next one is plaintext.
    send(&mut net, local(b"next"), false);
    net.pump();
    assert_eq!(net.plaintext[0].len(), 1);
    assert_eq!(net.take_delivered(1), []);
}

#[test]
fn the_mark_is_kept_across_an_update_and_absent_after_remove_and_re_add() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, false);
    net.handshake(0, 1);
    let peer = net.peer_id(0, 1);
    assert!(net.cores[0].set_plaintext_egress(peer, true));

    // An update in place keeps the id and the mark.
    let mut update = net.peer_config(1);
    update.persistent_keepalive = Some(25);
    update.allowed_ips.push(AllowedIp {
        addr: "10.9.0.0".parse().unwrap(),
        cidr: 24,
    });
    net.configure(0, ConfigChange::AddOrUpdatePeer(update));
    assert_eq!(net.peer_id(0, 1), peer);
    net.clear_logs();
    send(&mut net, local(b"updated"), false);
    net.pump();
    assert_eq!(net.plaintext[0].len(), 1);

    // Removed and added again: a new id, unmarked.
    net.configure(0, ConfigChange::RemovePeer(net.public_key(1)));
    assert!(!net.cores[0].set_plaintext_egress(peer, true));
    net.add_peer(0, 1);
    let new = net.peer_id(0, 1);
    assert_ne!(new, peer);
    net.clear_logs();
    net.handshake(0, 1);
    send(&mut net, local(b"re-added"), false);
    net.pump();
    assert_eq!(net.plaintext[0].len(), 0);
    let delivered: Vec<_> = net.take_delivered(1).into_iter().map(|(_, p)| p).collect();
    assert_eq!(delivered, [udp4(ip4(0), ip4(1), b"re-added")]);
}

#[test]
fn the_add_closed_read_back_mark_open_order_seals_nothing() {
    let mut net = Net::unpeered(2, |_| CoreConfig::default());
    net.add_peer(1, 0);
    // Added closed: no allowed IPs, so nothing is routed to it yet.
    let mut closed = net.peer_config(1);
    closed.allowed_ips.clear();
    net.configure(0, ConfigChange::AddOrUpdatePeer(closed));
    net.send_local(0, &udp4(ip4(0), ip4(1), b"closed"));
    let peer = net.peer_id(0, 1);
    assert!(net.cores[0].set_plaintext_egress(peer, true));
    net.configure(
        0,
        ConfigChange::SetAllowedIps {
            peer: net.public_key(1),
            allowed_ips: net.peer_config(1).allowed_ips,
        },
    );
    net.send_local(0, &udp4(ip4(0), ip4(1), b"open"));
    net.pump();

    // The packet before the peer was open had no route; the one after is plaintext. No
    // datagram was transmitted: no data, and no handshake for data.
    assert_eq!(sent_kinds(&net), [0_u8; 0]);
    assert!(net.take_events(0).contains(&Event::Dropped {
        peer: None,
        reason: nsplane_core::reasons::NO_ROUTE,
    }));
    let plain: Vec<_> = net.plaintext[0]
        .iter()
        .map(|(to, p)| (*to, p.as_packet().to_vec()))
        .collect();
    assert_eq!(plain, [(peer, udp4(ip4(0), ip4(1), b"open"))]);
}

#[test]
fn a_marked_peer_starts_no_handshake_for_data() {
    for crypto_jobs in [false, true] {
        let filter = Arc::new(Outbound::default());
        let mut net = net(&filter, crypto_jobs);
        let peer = net.peer_id(0, 1);
        assert!(net.cores[0].set_plaintext_egress(peer, true));
        net.clear_logs();
        for _ in 0..3 {
            send(&mut net, local(b"no handshake"), crypto_jobs);
        }
        net.run_for(Duration::from_secs(30));
        assert_eq!(sent_kinds(&net), [0_u8; 0]);
        assert_eq!(net.plaintext[0].len(), 3);
        assert_eq!(net.cores[0].peer_has_session(peer), Some(false));
    }
}

#[test]
fn a_marked_peer_answers_handshakes_and_delivers_inbound_sealed_traffic() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, false);
    let peer = net.peer_id(0, 1);
    assert!(net.cores[0].set_plaintext_egress(peer, true));
    net.clear_logs();
    // Core 1 initiates; core 0 answers.
    net.handshake(1, 0);
    assert_eq!(net.cores[0].peer_has_session(peer), Some(true));
    let packet = net.ping4(1, 0, b"inbound");
    assert_eq!(net.take_delivered(0), [(peer, packet)]);
    // Core 0's own data to the peer stays plaintext.
    send(&mut net, local(b"outbound"), false);
    net.pump();
    assert_eq!(net.plaintext[0].len(), 1);
    assert_eq!(net.take_delivered(1), []);
}

#[test]
fn a_marked_peer_starts_handshakes_for_inbound_sealed_traffic() {
    let filter = Arc::new(Outbound::default());
    let mut net = net(&filter, false);
    let peer = net.peer_id(0, 1);
    assert!(net.cores[0].set_plaintext_egress(peer, true));
    // Core 0 initiates the session (a forced handshake is not data).
    net.handshake(0, 1);
    let completed = |net: &mut Net| {
        net.take_events(0)
            .into_iter()
            .filter(|e| matches!(e, Event::HandshakeCompleted { .. }))
            .count()
    };
    let mut handshakes = completed(&mut net);
    assert_eq!(handshakes, 1);
    // The peer keeps sending sealed data while core 0's own packets leave as plaintext. As
    // the initiator, core 0 renews the session for the inbound traffic before it expires.
    for _ in 0..40 {
        net.ping4(1, 0, b"inbound");
        send(&mut net, local(b"outbound"), false);
        net.run_for(Duration::from_secs(5));
        handshakes += completed(&mut net);
    }
    assert!(handshakes >= 2, "{handshakes}");
    assert_eq!(net.take_delivered(0).len(), 40);
    assert_eq!(net.plaintext[0].len(), 40);
    assert_eq!(net.take_delivered(1), []);
}
