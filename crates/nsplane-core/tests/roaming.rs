//! Roaming: the standard policy adopting new paths, cookie replies that never roam, and custom
//! path policies.

#![cfg(feature = "mock-instant")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Fate, Net};
use nsplane_core::{
    CoreConfig, Ecn, Event, MessageKind, Path, PathPolicy, PeerId, Roam, StandardRoaming,
    TransportId,
};

/// A path on another transport and address than any core of the harness.
fn elsewhere() -> Path {
    Path {
        transport: TransportId::new(7),
        addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 40000)),
        ecn: Ecn::NotEct,
    }
}

/// `path` on another transport; datagrams still reach the same address.
const fn other_transport(path: Path, transport: u16) -> Path {
    Path {
        transport: TransportId::new(transport),
        ..path
    }
}

/// The `Authenticated` and `PathAdopted` events in `events`.
fn roaming(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .filter(|e| matches!(e, Event::Authenticated { .. } | Event::PathAdopted { .. }))
        .cloned()
        .collect()
}

fn roamed(peer: PeerId, path: Path) -> Vec<Event> {
    vec![
        Event::Authenticated { peer, from: path },
        Event::PathAdopted { peer, path },
    ]
}

/// Data from core 0 on `moved` makes core 1 adopt it; replies follow, and data on the adopted
/// path is event-free.
fn data_roams_to(moved: Path) {
    let mut net = Net::new(2);
    let b_to_a = net.peer_id(1, 0);
    net.ping4(0, 1, b"before");
    net.ping4(1, 0, b"before");
    net.clear_logs();

    net.paths[0] = moved;
    let packet = net.ping4(0, 1, b"from the new path");
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    assert_eq!(net.take_events(1), roamed(b_to_a, moved));
    assert_eq!(net.cores[1].peer_stats(b_to_a).unwrap().path, Some(moved));

    net.ping4(1, 0, b"back on the new path");
    assert_eq!(net.take_delivered(0).len(), 1);
    let transmits = net.take_transmits(1);
    assert_ne!(transmits, []);
    assert!(transmits.iter().all(|t| t.path == moved), "{transmits:?}");

    net.ping4(0, 1, b"unchanged path");
    assert_eq!(net.take_delivered(1).len(), 1);
    assert_eq!(net.take_events(1), []);
}

#[test]
fn data_from_a_new_address_roams() {
    data_roams_to(elsewhere());
}

#[test]
fn data_on_a_new_transport_roams() {
    data_roams_to(other_transport(common::path(0), 5));
}

#[test]
fn handshake_initiation_from_a_new_path_roams() {
    let mut net = Net::new(2);
    let b_to_a = net.peer_id(1, 0);
    let moved = elsewhere();
    net.paths[0] = moved;

    // The response already goes to the new path, so the handshake completes.
    let packet = net.ping4(0, 1, b"first packet");
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);
    assert_eq!(roaming(&net.take_events(1)), roamed(b_to_a, moved));
    let transmits = net.take_transmits(1);
    assert_eq!(transmits[0].data[0], 2, "a handshake response");
    assert!(transmits.iter().all(|t| t.path == moved), "{transmits:?}");
}

#[test]
fn handshake_response_from_a_new_path_roams() {
    let mut net = Net::new(2);
    let a_to_b = net.peer_id(0, 1);
    // Same address, so the initiation still reaches core 1; the response comes back on
    // another transport.
    let moved = other_transport(net.paths[1], 9);
    net.paths[1] = moved;

    net.handshake(0, 1);
    assert_eq!(roaming(&net.take_events(0)), roamed(a_to_b, moved));
    assert_eq!(net.cores[0].peer_stats(a_to_b).unwrap().path, Some(moved));
    net.ping4(0, 1, b"after");
    assert_eq!(net.take_delivered(1).len(), 1);
    let transmits = net.take_transmits(0);
    assert!(
        transmits[1..].iter().all(|t| t.path == moved),
        "{transmits:?}"
    );
}

/// Port of the removed `device::tests::cookie_replies_do_not_roam`, at the Core level: a cookie
/// reply arriving on a foreign path neither reports nor adopts it.
#[test]
fn cookie_replies_do_not_roam() {
    // Core 1 is always under load and answers handshakes without a cookie with a cookie reply.
    let mut net = Net::with_configs(2, |i| CoreConfig {
        handshake_rate_limit: if i == 1 { 0 } else { 100 },
        ..CoreConfig::default()
    });
    let a_to_b = net.peer_id(0, 1);
    let spoofed = elsewhere();
    net.set_interceptor(move |d| {
        if d.data.as_packet()[0] == 3 {
            d.arrival = spoofed;
        }
        Fate::Pass
    });

    net.handshake(0, 1);
    assert!(net.take_transmits(1).iter().all(|t| t.data[0] == 3));
    assert_eq!(roaming(&net.take_events(0)), []);
    assert_eq!(
        net.cores[0].peer_stats(a_to_b).unwrap().path,
        Some(net.paths[1])
    );

    // The retry carries the cookie and gets through, on the configured path.
    net.run_for(Duration::from_secs(6));
    let events = net.take_events(0);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::HandshakeCompleted { .. })),
        "{events:?}"
    );
    assert_eq!(roaming(&events), []);
    assert_eq!(
        net.cores[0].peer_stats(a_to_b).unwrap().path,
        Some(net.paths[1])
    );
}

/// Reports every new path but never adopts one.
#[derive(Debug)]
struct KeepPath;

impl PathPolicy for KeepPath {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        None
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
    }
}

#[test]
fn a_keeping_policy_does_not_roam() {
    let mut net = Net::with_configs(2, |_| CoreConfig {
        policy: Box::new(KeepPath),
        ..CoreConfig::default()
    });
    let b_to_a = net.peer_id(1, 0);
    net.ping4(0, 1, b"before");
    net.clear_logs();

    let configured = net.paths[0];
    let moved = other_transport(configured, 5);
    net.paths[0] = moved;
    net.ping4(0, 1, b"from the new path");
    assert_eq!(net.take_delivered(1).len(), 1);
    assert_eq!(
        net.take_events(1),
        [Event::Authenticated {
            peer: b_to_a,
            from: moved
        }]
    );

    net.ping4(1, 0, b"back on the old path");
    assert_eq!(net.take_delivered(0).len(), 1);
    let transmits = net.take_transmits(1);
    assert!(
        transmits.iter().all(|t| t.path == configured),
        "{transmits:?}"
    );
    assert_eq!(
        net.cores[1].peer_stats(b_to_a).unwrap().path,
        Some(configured)
    );
}

/// Sends handshake initiations and data through two relays, everything else on the current
/// path; roams like [`StandardRoaming`].
#[derive(Debug)]
struct Relays {
    handshake: Path,
    data: Path,
}

impl PathPolicy for Relays {
    fn select(&self, _peer: PeerId, kind: MessageKind) -> Option<Path> {
        match kind {
            MessageKind::HandshakeInit => Some(self.handshake),
            MessageKind::Data => Some(self.data),
            MessageKind::HandshakeResponse | MessageKind::CookieReply | MessageKind::Keepalive => {
                None
            }
        }
    }

    fn on_authenticated(&self, peer: PeerId, from: &Path, kind: MessageKind) -> Roam {
        StandardRoaming.on_authenticated(peer, from, kind)
    }
}

#[test]
fn the_policy_selects_a_path_per_message_kind() {
    // The relays are other transports to core 1's address.
    let handshake = other_transport(common::path(1), 100);
    let data = other_transport(common::path(1), 101);
    let mut net = Net::with_configs(2, |i| CoreConfig {
        policy: if i == 0 {
            Box::new(Relays { handshake, data })
        } else {
            Box::new(StandardRoaming)
        },
        ..CoreConfig::default()
    });

    let packet = net.ping4(0, 1, b"through the relays");
    assert_eq!(net.take_delivered(1)[0].1, packet);
    let packet = net.ping6(0, 1, b"again");
    assert_eq!(net.take_delivered(1)[0].1, packet);

    let transmits = net.take_transmits(0);
    let paths: Vec<(u8, usize, Path)> = transmits
        .iter()
        .map(|t| (t.data[0], t.data.len(), t.path))
        .collect();
    assert!(paths.iter().any(|&(kind, ..)| kind == 1), "{paths:?}");
    for (kind, len, path) in paths {
        let expected = match (kind, len) {
            (1, _) => handshake,
            (4, 32) => net.paths[1],
            (4, _) => data,
            _ => panic!("unexpected message {kind} of {len} bytes"),
        };
        assert_eq!(path, expected, "message {kind} of {len} bytes");
    }
}
