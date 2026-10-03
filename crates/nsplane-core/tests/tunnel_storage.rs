//! Both tunnel storages (owned by the peer, or shared with crypto jobs behind a lock) behave
//! the same through `Core::handle_input` and the timers.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::time::Duration;

use common::Net;
use nsplane_core::x25519::PublicKey;
use nsplane_core::{ConfigChange, CoreConfig, Event, PeerId, PeerStats};

/// What a scenario produced on each core, without the ciphertexts.
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    delivered: Vec<Vec<(PeerId, Vec<u8>)>>,
    /// Events, with the measured handshake round trip times (taken on the real clock)
    /// cleared.
    events: Vec<Vec<Event>>,
    /// Lengths of the transmitted datagrams.
    transmits: Vec<Vec<usize>>,
    /// Peer stats, with the (random) public keys cleared.
    stats: Vec<PeerStats>,
}

/// Handshake, data in both directions over IPv4 and IPv6, then the timers: persistent
/// keepalives and the expiry of every session.
fn scenario(crypto_jobs: bool) -> Trace {
    let mut net = Net::with_configs(2, |_| CoreConfig {
        crypto_jobs,
        ..CoreConfig::default()
    });
    net.ping4(0, 1, b"hello over v4");
    net.ping4(1, 0, b"and back");
    net.ping6(0, 1, b"hello over v6");
    net.ping6(1, 0, b"and back over v6");
    let key = net.public_key(1);
    net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer: key,
            interval: Some(10),
        },
    );
    net.run_for(Duration::from_secs(150));
    net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer: key,
            interval: None,
        },
    );
    net.run_for(Duration::from_secs(600));

    let stats = [(0, 1), (1, 0)]
        .map(|(i, j)| PeerStats {
            public_key: PublicKey::from([0; 32]),
            ..net.cores[i].peer_stats(net.peer_id(i, j)).unwrap()
        })
        .into();
    Trace {
        delivered: (0..2).map(|i| net.take_delivered(i)).collect(),
        events: (0..2)
            .map(|i| {
                let mut events = net.take_events(i);
                for event in &mut events {
                    if let Event::HandshakeCompleted { rtt, .. } = event {
                        *rtt = None;
                    }
                }
                events
            })
            .collect(),
        transmits: (0..2)
            .map(|i| net.take_transmits(i).iter().map(|t| t.data.len()).collect())
            .collect(),
        stats,
    }
}

#[test]
fn owned_and_shared_tunnels_behave_the_same() {
    let owned = scenario(false);
    assert_eq!(owned.delivered.iter().map(Vec::len).sum::<usize>(), 4);
    assert!(
        owned.transmits[0].iter().filter(|&&len| len == 32).count() > 10,
        "persistent keepalives: {:?}",
        owned.transmits[0]
    );
    for events in &owned.events {
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::SessionExpired { .. })),
            "the sessions expired: {events:?}"
        );
    }
    assert!(owned.stats.iter().all(|s| s.data_rx > 0 && s.data_tx > 0));
    assert_eq!(owned, scenario(true));
}
