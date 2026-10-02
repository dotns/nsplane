//! Several peers per core: routing by allowed IPs, peers sharing one path, concurrent traffic
//! and endpoint changes.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use common::{Fate, Net, default_config, ip4, ip6, udp4, udp6};
use nsplane_core::{ConfigChange, Ecn, Event, Path, PeerConfig, PeerId, TransportId};

/// Core `j` as a peer with these allowed IPs on its harness path.
fn peer_with(net: &Net, j: usize, allowed_ips: &[&str]) -> ConfigChange {
    let mut config = PeerConfig::new(net.public_key(j));
    config.allowed_ips = allowed_ips.iter().map(|ip| ip.parse().unwrap()).collect();
    config.path = Some(net.paths[j]);
    ConfigChange::AddOrUpdatePeer(config)
}

/// A hub (core 0) and two spokes that route the whole tunnel network to the hub. The hub
/// routes `10.0.0.0/16` to spoke 1 and only `10.0.0.3/32` (spoke 2's address) to spoke 2.
fn hub_and_spokes() -> Net {
    let mut net = Net::unpeered(3, default_config);
    let change = peer_with(&net, 1, &["10.0.0.0/16", "fd00::/64"]);
    net.configure(0, change);
    let change = peer_with(&net, 2, &["10.0.0.3/32", "fd00::3/128"]);
    net.configure(0, change);
    for j in [1, 2] {
        let change = peer_with(&net, 0, &["10.0.0.0/24", "fd00::/64"]);
        net.configure(j, change);
    }
    net.pump();
    net
}

#[test]
fn a_hub_routes_by_the_longest_allowed_ip_match() {
    let mut net = hub_and_spokes();
    let (hub_to_1, hub_to_2) = (net.peer_id(0, 1), net.peer_id(0, 2));
    let (s1_to_hub, s2_to_hub) = (net.peer_id(1, 0), net.peer_id(2, 0));

    let packet = net.ping4(1, 0, b"to the hub");
    assert_eq!(net.take_delivered(0), [(hub_to_1, packet)]);

    // Between the spokes, through the hub acting as the driver that forwards.
    let routes = [(1, 2, hub_to_1, s2_to_hub), (2, 1, hub_to_2, s1_to_hub)];
    for (from, to, hub_from, spoke_from) in routes {
        for packet in [
            udp4(ip4(from), ip4(to), b"spoke to spoke over v4"),
            udp6(ip6(from), ip6(to), b"spoke to spoke over v6"),
        ] {
            net.send_local(from, &packet);
            net.pump();
            assert_eq!(net.take_delivered(0), [(hub_from, packet.clone())]);
            net.send_local(0, &packet);
            net.pump();
            assert_eq!(net.take_delivered(to), [(spoke_from, packet)]);
            assert_eq!(net.take_delivered(from), []);
        }
    }

    // Addresses only the shorter prefixes cover go to spoke 1.
    for packet in [
        udp4(ip4(0), Ipv4Addr::new(10, 0, 5, 5), b"wide v4"),
        udp6(ip6(0), "fd00::55".parse().unwrap(), b"wide v6"),
    ] {
        net.send_local(0, &packet);
        net.pump();
        assert_eq!(net.take_delivered(1), [(s1_to_hub, packet)]);
        assert_eq!(net.take_delivered(2), []);
    }
}

/// A relay at `relay` for the clients (cores 1 and 2) of core 0: it learns the session index
/// of each client from its handshake messages and forwards core 0's datagrams by receiver
/// index.
fn relay_clients(net: &mut Net, relay: Path) {
    let paths = net.paths.clone();
    let mut sessions: HashMap<u32, usize> = HashMap::new();
    net.set_interceptor(move |d| {
        let data = d.data.as_packet();
        let index = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
        if d.from == 0 {
            // A response names the receiver after the sender; the other messages first.
            let receiver = if data[0] == 2 { index(8) } else { index(4) };
            d.path.addr = paths[sessions[&receiver]].addr;
        } else {
            if matches!(data[0], 1 | 2) {
                sessions.insert(index(4), d.from);
            }
            d.arrival = relay;
        }
        Fate::Pass
    });
}

#[test]
fn peers_behind_one_path_are_told_apart_by_their_static_keys() {
    let relay = Path {
        transport: TransportId::new(42),
        addr: SocketAddr::from((Ipv4Addr::new(203, 0, 113, 1), 3478)),
        ecn: Ecn::NotEct,
    };
    let mut net = Net::unpeered(3, default_config);
    for j in [1, 2] {
        // The server learns the path from the first handshake.
        let mut config = net.peer_config(j);
        config.path = None;
        net.configure(0, ConfigChange::AddOrUpdatePeer(config));
        net.add_peer(j, 0);
    }
    relay_clients(&mut net, relay);
    let clients = [net.peer_id(0, 1), net.peer_id(0, 2)];

    // Both initiations are in flight at once and arrive on the same path.
    let first = [
        udp4(ip4(1), ip4(0), b"first from 1"),
        udp4(ip4(2), ip4(0), b"first from 2"),
    ];
    net.send_local(1, &first[0]);
    net.send_local(2, &first[1]);
    net.pump();
    let mut delivered = net.take_delivered(0);
    delivered.sort();
    assert_eq!(
        delivered,
        [
            (clients[0], first[0].clone()),
            (clients[1], first[1].clone())
        ]
    );
    let events = net.take_events(0);
    for peer in clients {
        let completed = Event::HandshakeCompleted {
            peer,
            path: Some(relay),
            rtt: None,
        };
        assert!(events.contains(&completed), "{events:?}");
        assert!(events.contains(&Event::PathAdopted { peer, path: relay }));
        assert_eq!(net.cores[0].peer_stats(peer).unwrap().path, Some(relay));
    }

    // Both sessions carry traffic at the same time, in both directions.
    for round in 0..10u8 {
        for client in [1, 2] {
            net.send_local(client, &udp4(ip4(client), ip4(0), &[round]));
            net.send_local(0, &udp6(ip6(0), ip6(client), &[round]));
        }
        net.pump();
        let mut delivered = net.take_delivered(0);
        delivered.sort();
        assert_eq!(
            delivered,
            [
                (clients[0], udp4(ip4(1), ip4(0), &[round])),
                (clients[1], udp4(ip4(2), ip4(0), &[round])),
            ]
        );
        for client in [1, 2] {
            let server = net.peer_id(client, 0);
            let packet = udp6(ip6(0), ip6(client), &[round]);
            assert_eq!(net.take_delivered(client), [(server, packet)]);
        }
    }
}

/// Port of the intent of the removed device tests `test_wg_concurrent` and `test_wg_concurrent_v6`: many
/// packets interleaved in both directions between several peers all arrive once and intact.
#[test]
fn concurrent_traffic_between_several_peers() {
    const CORES: usize = 4;
    const ROUNDS: usize = 25;
    let mut net = Net::new(CORES);
    for i in 0..CORES {
        for j in i + 1..CORES {
            net.handshake(i, j);
        }
    }
    net.clear_logs();

    let mut expected: Vec<Vec<(PeerId, Vec<u8>)>> = vec![Vec::new(); CORES];
    for round in 0..ROUNDS {
        for i in 0..CORES {
            for j in (0..CORES).filter(|&j| j != i) {
                let payload = format!("{i} -> {j} #{round}").into_bytes();
                let packet = if (round + i + j) % 2 == 0 {
                    udp4(ip4(i), ip4(j), &payload)
                } else {
                    udp6(ip6(i), ip6(j), &payload)
                };
                net.send_local(i, &packet);
                expected[j].push((net.peer_id(j, i), packet));
            }
        }
        // Let several rounds pile up before they move.
        if round % 5 == 4 {
            net.pump();
        }
    }
    net.pump();

    for (j, mut expected) in expected.into_iter().enumerate() {
        let mut delivered = net.take_delivered(j);
        delivered.sort();
        expected.sort();
        assert_eq!(delivered.len(), (CORES - 1) * ROUNDS);
        assert_eq!(delivered, expected, "core {j}");
        assert_eq!(net.take_events(j), [], "core {j}");
    }
}

/// An IPv6 endpoint for core `i`.
fn v6_endpoint(i: usize, port: u16) -> Path {
    let host = u16::try_from(i + 1).unwrap();
    Path {
        addr: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, host)),
            port,
        ),
        ..common::path(i)
    }
}

fn pings_both_ways(net: &mut Net) {
    let (a_to_b, b_to_a) = (net.peer_id(0, 1), net.peer_id(1, 0));
    let packet = net.ping4(0, 1, b"v4 there");
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    let packet = net.ping6(1, 0, b"v6 back");
    assert_eq!(net.take_delivered(0), [(a_to_b, packet)]);
}

/// Port of the intent of the removed device tests `test_wg_start_ipv6_endpoint`: a peer configured with an
/// IPv6 endpoint carries v4 and v6 traffic.
#[test]
fn a_peer_starts_on_an_ipv6_endpoint() {
    let mut net = Net::unpeered(2, default_config);
    net.paths[1] = v6_endpoint(1, 51820);
    net.add_peer(0, 1);
    net.add_peer(1, 0);
    pings_both_ways(&mut net);

    let transmits = net.take_transmits(0);
    assert!(
        transmits.iter().all(|t| t.path == net.paths[1]),
        "{transmits:?}"
    );
}

/// The endpoint of a peer changes by configuration and traffic follows it, without roaming
/// events. With `a_peer_starts_on_an_ipv6_endpoint`, this covers the protocol side of
/// the removed `test_wg_start_ipv6_endpoint*`; their connected/unconnected socket variants
/// have no Core-level counterpart.
#[test]
fn traffic_follows_a_configured_endpoint_change() {
    let mut net = Net::new(2);
    pings_both_ways(&mut net);
    net.clear_logs();

    // Core 1 moves; core 0 still sends to the old endpoint.
    let moved = v6_endpoint(1, 51821);
    net.paths[1] = moved;
    net.ping4(0, 1, b"to the old endpoint");
    assert_eq!(net.take_delivered(1), []);
    assert_eq!(net.lost.len(), 1);
    assert_eq!(net.take_transmits(0)[0].path, common::path(1));

    let peer = net.public_key(1);
    net.configure(0, ConfigChange::SetPath { peer, path: moved });
    pings_both_ways(&mut net);
    let transmits = net.take_transmits(0);
    assert!(transmits.iter().all(|t| t.path == moved), "{transmits:?}");
    assert_eq!(net.take_events(0), []);
    assert_eq!(
        net.cores[0].peer_stats(net.peer_id(0, 1)).unwrap().path,
        Some(moved)
    );
}
