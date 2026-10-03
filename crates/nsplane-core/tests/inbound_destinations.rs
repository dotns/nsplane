//! Per-peer inbound destinations: core 1 restricts where core 0's decrypted packets may go,
//! on every receive path (per packet, batched, deferred), and changes the set at runtime.
//! Core 0 routes `10.1.0.0/16` and `fd01::/64` to core 1 besides core 1's own addresses, so
//! it can send to destinations core 1 does not own.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{Net, ip4, ip6, udp4, udp6};
use nsplane_core::{
    AllowedIp, ConfigChange, Core, CoreConfig, CryptoJob, Event, Input, PeerConfig, reasons,
};

const OTHER4: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 5);
const OTHER6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 5);

fn cidr(s: &str) -> AllowedIp {
    s.parse().unwrap()
}

/// Two cores (with crypto jobs if `crypto_jobs`); core 0 routes the extra networks to core 1
/// and core 1 knows core 0 with `destinations`.
fn pair(crypto_jobs: bool, destinations: Option<Vec<AllowedIp>>) -> Net {
    let mut net = Net::with_configs(2, |_| CoreConfig {
        crypto_jobs,
        ..CoreConfig::default()
    });
    let mut config = net.peer_config(1);
    config
        .allowed_ips
        .extend([cidr("10.1.0.0/16"), cidr("fd01::/64")]);
    net.configure(0, ConfigChange::AddOrUpdatePeer(config));
    let config = PeerConfig {
        inbound_destinations: destinations,
        ..net.peer_config(0)
    };
    net.configure(1, ConfigChange::AddOrUpdatePeer(config));
    net
}

fn drops(net: &mut Net) -> Vec<&'static str> {
    net.take_events(1)
        .into_iter()
        .filter_map(|e| match e {
            Event::Dropped { reason, .. } => Some(reason),
            _ => None,
        })
        .collect()
}

/// Sends `packet` from core 0 and returns whether core 1 delivered it; a packet it did not
/// deliver must have been dropped as not allowed.
fn passes(net: &mut Net, packet: &[u8]) -> bool {
    net.send_local(0, packet);
    net.pump();
    let delivered = net.take_delivered(1);
    let drops = drops(net);
    if delivered.is_empty() {
        assert_eq!(drops, [reasons::DESTINATION_NOT_ALLOWED]);
        false
    } else {
        assert_eq!(delivered, [(net.peer_id(1, 0), packet.to_vec())]);
        assert_eq!(drops, Vec::<&str>::new());
        true
    }
}

fn v4(dst: Ipv4Addr) -> Vec<u8> {
    udp4(ip4(0), dst, b"v4")
}

fn v6(dst: Ipv6Addr) -> Vec<u8> {
    udp6(ip6(0), dst, b"v6")
}

#[test]
fn reason() {
    assert_eq!(reasons::DESTINATION_NOT_ALLOWED, "destination not allowed");
}

#[test]
fn a_peer_without_inbound_destinations_is_unchecked() {
    let mut net = pair(false, None);
    assert!(passes(&mut net, &v4(ip4(1))));
    assert!(passes(&mut net, &v4(OTHER4)));
    assert!(passes(&mut net, &v6(OTHER6)));
}

#[test]
fn only_listed_destinations_pass() {
    let mut net = pair(false, Some(vec![cidr("10.0.0.2/32"), cidr("fd01::/64")]));
    assert!(passes(&mut net, &v4(ip4(1))));
    assert!(!passes(&mut net, &v4(OTHER4)));
    assert!(passes(&mut net, &v6(OTHER6)));
    assert!(!passes(&mut net, &v6(ip6(1))));

    let peer = net.peer_id(1, 0);
    net.send_local(0, &v4(OTHER4));
    net.pump();
    assert_eq!(
        net.take_events(1),
        [Event::Dropped {
            peer: Some(peer),
            reason: reasons::DESTINATION_NOT_ALLOWED
        }]
    );
}

#[test]
fn an_empty_set_drops_every_packet_but_not_keepalives() {
    let mut net = pair(false, Some(Vec::new()));
    // The handshake ends with core 0's keepalive confirming the session to core 1.
    net.handshake(0, 1);
    assert!(
        net.take_events(1)
            .iter()
            .any(|e| matches!(e, Event::HandshakeCompleted { .. }))
    );
    assert!(!passes(&mut net, &v4(ip4(1))));
    assert!(!passes(&mut net, &v6(ip6(1))));
}

#[test]
fn updates_keep_or_replace_and_changes_set_or_clear() {
    let mut net = pair(false, Some(vec![cidr("10.0.0.2/32")]));
    let a = net.public_key(0);

    // An update without inbound destinations keeps them.
    net.configure(1, ConfigChange::AddOrUpdatePeer(PeerConfig::new(a)));
    assert!(passes(&mut net, &v4(ip4(1))));
    assert!(!passes(&mut net, &v4(OTHER4)));

    // An update with them replaces them.
    let config = PeerConfig {
        inbound_destinations: Some(vec![cidr("10.1.0.0/16")]),
        ..PeerConfig::new(a)
    };
    net.configure(1, ConfigChange::AddOrUpdatePeer(config));
    assert!(!passes(&mut net, &v4(ip4(1))));
    assert!(passes(&mut net, &v4(OTHER4)));

    net.configure(
        1,
        ConfigChange::SetInboundDestinations {
            peer: a,
            destinations: Some(vec![cidr("10.0.0.2/32")]),
        },
    );
    assert!(passes(&mut net, &v4(ip4(1))));
    assert!(!passes(&mut net, &v4(OTHER4)));

    net.configure(
        1,
        ConfigChange::SetInboundDestinations {
            peer: a,
            destinations: None,
        },
    );
    assert!(passes(&mut net, &v4(OTHER4)));
    assert!(passes(&mut net, &v6(OTHER6)));
}

#[test]
fn a_removed_peer_loses_its_inbound_destinations() {
    let mut net = pair(false, Some(Vec::new()));
    let a = net.public_key(0);
    net.configure(1, ConfigChange::RemovePeer(a));
    net.add_peer(1, 0);
    assert!(passes(&mut net, &v4(OTHER4)));

    net.configure(
        1,
        ConfigChange::SetInboundDestinations {
            peer: a,
            destinations: Some(Vec::new()),
        },
    );
    net.configure(1, ConfigChange::RemoveAllPeers);
    net.add_peer(1, 0);
    // Core 0 still holds the session of the removed peer: start a new one.
    net.handshake(1, 0);
    net.take_events(1);
    assert!(passes(&mut net, &v4(OTHER4)));
}

/// Runs the jobs, then completes them in order.
fn complete(core: &mut Core, mut jobs: Vec<CryptoJob>) {
    jobs.iter_mut().for_each(CryptoJob::run);
    for job in jobs {
        core.complete_job(job);
    }
}

#[test]
fn every_receive_path_checks_every_packet() {
    for (crypto_jobs, batch) in [(false, true), (true, false), (true, true)] {
        let mut net = pair(crypto_jobs, Some(vec![cidr("10.0.0.2/32")]));
        net.handshake(0, 1);
        net.take_events(1);
        let allowed = v4(ip4(1));
        let denied = v4(OTHER4);
        // Alternate, so a cached lookup for one packet must not decide the next.
        let packets = [&allowed, &denied, &allowed, &allowed, &denied, &denied];
        for packet in packets {
            net.send_local(0, packet);
        }
        let in_flight: Vec<_> = net
            .drain()
            .into_iter()
            .map(|d| (d.arrival, d.data))
            .collect();
        assert_eq!(in_flight.len(), packets.len());

        let now = net.now;
        let core = &mut net.cores[1];
        let mut jobs = Vec::new();
        match (crypto_jobs, batch) {
            (false, _) => core.handle_datagrams(in_flight, now),
            (true, true) => core.handle_datagrams_deferred(in_flight, now, &mut jobs),
            (true, false) => {
                jobs = in_flight
                    .into_iter()
                    .filter_map(|(path, data)| {
                        core.handle_input_deferred(Input::Datagram { path, data }, now)
                    })
                    .collect();
            }
        }
        complete(core, jobs);
        net.pump();

        let peer = net.peer_id(1, 0);
        assert_eq!(
            net.take_delivered(1),
            vec![(peer, allowed.clone()); 3],
            "{crypto_jobs} {batch}"
        );
        assert_eq!(
            drops(&mut net),
            [reasons::DESTINATION_NOT_ALLOWED; 3],
            "{crypto_jobs} {batch}"
        );
    }
}
