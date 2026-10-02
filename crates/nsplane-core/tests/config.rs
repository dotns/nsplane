//! Configuration changes on live cores: removing peers, allowed IPs, preshared keys, the
//! private key, peer stats and forced handshakes.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Net, ip4, udp4};
use nsplane_core::x25519::StaticSecret;
use nsplane_core::{AllowedIp, ConfigChange, CoreConfig, Event, Output, Path};
use rand_core::OsRng;

fn handshakes(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::HandshakeCompleted { .. }))
        .count()
}

fn dropped(events: &[Event]) -> Vec<&'static str> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Dropped { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect()
}

fn cidr(s: &str) -> AllowedIp {
    s.parse().unwrap()
}

/// Moves on by one timer tick: the next initiation is not a replay, and the tunnels, whose
/// clocks only move with their timers, tell the next session from the current one.
fn tick(net: &mut Net) {
    net.advance(Duration::from_millis(250));
}

#[test]
fn removed_peer_gets_no_traffic_and_a_new_id_when_added_again() {
    let mut net = Net::new(2);
    net.ping4(0, 1, b"hello");
    net.ping4(1, 0, b"hello");
    let old = net.peer_id(0, 1);
    net.clear_logs();

    let peer = net.public_key(1);
    net.configure(0, ConfigChange::RemovePeer(peer));
    assert_eq!(net.cores[0].peer_id(&peer), None);
    assert_eq!(net.cores[0].peer_stats(old), None);
    net.ping4(0, 1, b"to nobody");
    assert_eq!(dropped(&net.take_events(0)), ["no route"]);
    net.ping4(1, 0, b"from nobody");
    assert_eq!(net.take_delivered(0), Vec::new());
    assert_eq!(dropped(&net.take_events(0)), ["unknown session"]);

    tick(&mut net);
    net.add_peer(0, 1);
    let new = net.peer_id(0, 1);
    assert_ne!(new, old);
    let packet = net.ping4(0, 1, b"back again");
    assert_eq!(net.take_delivered(1).last().unwrap().1, packet);
    let packet = net.ping4(1, 0, b"welcome back");
    assert_eq!(net.take_delivered(0), [(new, packet)]);
}

#[test]
fn remove_all_peers() {
    let mut net = Net::new(3);
    net.ping4(0, 1, b"hello");
    net.ping4(0, 2, b"hello");
    net.clear_logs();

    net.configure(0, ConfigChange::RemoveAllPeers);
    assert_eq!(net.cores[0].peers().count(), 0);
    net.ping4(0, 1, b"gone");
    net.ping4(0, 2, b"gone");
    assert_eq!(dropped(&net.take_events(0)), ["no route", "no route"]);
    assert_eq!(net.take_transmits(0), Vec::new());
}

#[test]
fn set_allowed_ips_replaces_ranges() {
    let mut net = Net::new(3);
    let (to_1, to_2) = (net.peer_id(0, 1), net.peer_id(0, 2));
    let range = cidr("10.1.0.0/16");
    let inside = Ipv4Addr::new(10, 1, 2, 3);

    let peer = net.public_key(1);
    net.configure(
        0,
        ConfigChange::SetAllowedIps {
            peer,
            allowed_ips: vec![range],
        },
    );
    assert_eq!(net.cores[0].peer_stats(to_1).unwrap().allowed_ips, [range]);
    net.ping4(0, 1, b"old range");
    assert_eq!(dropped(&net.take_events(0)), ["no route"]);
    let packet = udp4(ip4(0), inside, b"new range");
    net.send_local(0, &packet);
    net.pump();
    assert_eq!(net.take_delivered(1).last().unwrap().1, packet);

    // The range moves to core 2, and the routing follows.
    let peer = net.public_key(2);
    net.configure(
        0,
        ConfigChange::SetAllowedIps {
            peer,
            allowed_ips: vec![range],
        },
    );
    assert_eq!(net.cores[0].peer_stats(to_1).unwrap().allowed_ips, []);
    assert_eq!(net.cores[0].peer_stats(to_2).unwrap().allowed_ips, [range]);
    net.send_local(0, &packet);
    net.pump();
    assert_eq!(net.take_delivered(2).last().unwrap().1, packet);
    assert_eq!(net.take_delivered(1), Vec::new());
}

fn set_psk(net: &mut Net, i: usize, j: usize, key: Option<[u8; 32]>) {
    let peer = net.public_key(j);
    net.configure(i, ConfigChange::SetPresharedKey { peer, key });
}

#[test]
fn preshared_key_mismatch_fails_and_match_completes() {
    let mut net = Net::new(2);
    set_psk(&mut net, 0, 1, Some([1; 32]));
    net.handshake(0, 1);
    assert_eq!(handshakes(&net.take_events(0)), 0);
    assert_eq!(
        net.cores[0]
            .peer_stats(net.peer_id(0, 1))
            .unwrap()
            .last_handshake,
        None
    );

    set_psk(&mut net, 1, 0, Some([1; 32]));
    tick(&mut net);
    net.handshake(0, 1);
    assert_eq!(handshakes(&net.take_events(0)), 1);
    let packet = net.ping4(0, 1, b"with a psk");
    assert_eq!(net.take_delivered(1).last().unwrap().1, packet);
}

/// Port of nsplane-noise `noise::tests::preshared_key_change_keeps_the_live_session`.
#[test]
fn preshared_key_change_keeps_the_live_session() {
    let mut net = Net::new(2);
    set_psk(&mut net, 0, 1, Some([1; 32]));
    set_psk(&mut net, 1, 0, Some([1; 32]));
    net.handshake(0, 1);
    net.clear_logs();

    set_psk(&mut net, 0, 1, Some([2; 32]));
    let packet = net.ping4(0, 1, b"same session");
    assert_eq!(net.take_delivered(1), [(net.peer_id(1, 0), packet)]);
    assert_eq!(handshakes(&net.take_events(0)), 0);
}

/// Port of nsplane-noise `noise::tests::preshared_key_change_applies_to_the_next_handshake`.
#[test]
fn preshared_key_change_applies_to_the_next_handshake() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();

    // Only one side has the new key: the next handshake fails.
    set_psk(&mut net, 0, 1, Some([2; 32]));
    tick(&mut net);
    net.handshake(0, 1);
    assert_eq!(handshakes(&net.take_events(0)), 0);

    set_psk(&mut net, 1, 0, Some([2; 32]));
    tick(&mut net);
    net.handshake(0, 1);
    assert_eq!(handshakes(&net.take_events(0)), 1);

    // Removing the key on both sides works too.
    set_psk(&mut net, 0, 1, None);
    set_psk(&mut net, 1, 0, None);
    tick(&mut net);
    net.handshake(0, 1);
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(
        net.cores[0]
            .peer_stats(net.peer_id(0, 1))
            .unwrap()
            .preshared_key,
        None
    );
}

#[test]
fn set_private_key_clears_sessions_and_handshakes_with_the_new_key() {
    let mut net = Net::new(2);
    net.ping4(0, 1, b"hello");
    let to_1 = net.peer_id(0, 1);
    let old_key = net.public_key(0);
    net.clear_logs();

    let key = StaticSecret::random_from_rng(OsRng);
    net.configure(0, ConfigChange::SetPrivateKey(key.clone()));
    net.keys[0] = key;
    assert_eq!(net.cores[0].public_key(), Some(net.public_key(0)));
    assert_eq!(net.cores[0].peer_stats(to_1).unwrap().last_handshake, None);

    // Core 1 still uses the old session, which core 0 no longer has.
    net.ping4(1, 0, b"old session");
    assert_eq!(net.take_delivered(0), Vec::new());
    assert_eq!(dropped(&net.take_events(0)), ["decapsulate error"]);

    // Core 1 does not know the new key yet.
    let packet = net.ping4(0, 1, b"new key");
    assert_eq!(dropped(&net.take_events(1)), ["unknown peer"]);

    net.configure(1, ConfigChange::RemovePeer(old_key));
    net.add_peer(1, 0);
    tick(&mut net);
    net.handshake(0, 1);
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(net.take_delivered(1), [(net.peer_id(1, 0), packet)]);
}

#[test]
fn peer_stats_reflect_config_and_traffic() {
    let mut net = Net::new(2);
    let mut config = net.peer_config(1);
    config.preshared_key = Some([7; 32]);
    config.persistent_keepalive = Some(25);
    net.configure(0, ConfigChange::AddOrUpdatePeer(config));
    let mut config = net.peer_config(0);
    config.preshared_key = Some([7; 32]);
    net.configure(1, ConfigChange::AddOrUpdatePeer(config));

    let id = net.peer_id(0, 1);
    let stats = net.cores[0].peer_stats(id).unwrap();
    assert_eq!((stats.rx, stats.tx, stats.data_rx), (0, 0, 0));
    assert_eq!(stats.last_handshake, None);

    let sent = net.ping4(0, 1, b"ping");
    let received = net.ping4(1, 0, b"pong!");
    net.advance(Duration::from_secs(2));
    let stats = net.cores[0].peer_stats(id).unwrap();
    assert_eq!(stats.peer, id);
    assert_eq!(stats.public_key, net.public_key(1));
    assert_eq!(stats.path, Some(net.paths[1]));
    assert_eq!(
        stats.allowed_ips.iter().copied().collect::<BTreeSet<_>>(),
        net.peer_config(1).allowed_ips.into_iter().collect()
    );
    assert_eq!(stats.preshared_key, Some([7; 32]));
    assert_eq!(stats.persistent_keepalive, Some(25));
    assert!(stats.tx >= sent.len() as u64, "{stats:?}");
    assert!(stats.rx >= received.len() as u64, "{stats:?}");
    assert_eq!(stats.data_rx, received.len() as u64);
    let since = stats.last_handshake.unwrap();
    assert!(since >= Duration::from_secs(2) && since < Duration::from_secs(3));
}

#[test]
fn stats_interval_emits_peer_stats() {
    let mut net = Net::with_configs(2, |i| CoreConfig {
        stats_interval: (i == 0).then_some(Duration::from_secs(2)),
        ..CoreConfig::default()
    });
    let id = net.peer_id(0, 1);
    let received = net.ping4(1, 0, b"counted");
    net.clear_logs();

    net.run_for(Duration::from_secs(6));
    let stats: Vec<_> = net
        .take_events(0)
        .into_iter()
        .filter_map(|e| match e {
            Event::PeerStats {
                peer,
                data_rx,
                last_handshake,
                ..
            } => Some((peer, data_rx, last_handshake.is_some())),
            _ => None,
        })
        .collect();
    assert_eq!(stats, [(id, received.len() as u64, true); 3]);
    assert!(net.take_events(1).is_empty(), "core 1 reports no stats");
}

#[test]
fn force_handshake_on_a_path_sends_an_initiation_there() {
    let mut net = Net::new(2);
    let id = net.peer_id(0, 1);
    let path = Path {
        addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 9), 51820)),
        ..net.paths[1]
    };

    net.cores[0].force_handshake(id, Some(path), net.now);
    let Some(Output::Transmit {
        path: sent_on,
        data,
    }) = net.cores[0].poll_output()
    else {
        panic!("expected an initiation");
    };
    assert_eq!(sent_on, path);
    assert_eq!((data.len(), data.as_packet()[0]), (148, 1));
    assert!(net.cores[0].poll_output().is_none(), "no PathAdopted");
    assert_eq!(net.cores[0].peer_stats(id).unwrap().path, Some(path));
}
