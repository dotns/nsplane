//! The handshake gate under load: cookie replies, the mac2 retry through the gate and the
//! peer's tunnel, the rate limiter reset, and garbage datagrams.

#![cfg(feature = "mock-instant")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Fate, Net, Sent, packet_buf};
use nstun_core::{CoreConfig, Event, Output, Path};

/// Handshakes per second the responder tolerates in these tests.
const LIMIT: u64 = 2;

/// Two cores whose handshake gates allow [`LIMIT`] handshakes per second.
fn net() -> Net {
    Net::with_configs(2, |_| CoreConfig {
        handshake_rate_limit: LIMIT,
        ..CoreConfig::default()
    })
}

fn is_cookie_reply(t: &Sent) -> bool {
    t.data.len() == 64 && t.data[0] == 3
}

fn handshakes(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::HandshakeCompleted { .. }))
        .count()
}

/// A handshake initiation from core 0 to core 1 that never reached the network.
fn captured_init(net: &mut Net) -> Vec<u8> {
    let peer = net.peer_id(0, 1);
    net.cores[0].force_handshake(peer, None, net.now);
    let Some(Output::Transmit { data, .. }) = net.cores[0].poll_output() else {
        panic!("expected an initiation");
    };
    assert!(net.cores[0].poll_output().is_none());
    data.as_packet().to_vec()
}

/// Replays `init` to core 1 from core 0's path `copies` times, and returns what core 1 sent
/// back; nothing of it reaches core 0.
fn flood(net: &mut Net, init: &[u8], copies: usize) -> Vec<Sent> {
    for _ in 0..copies {
        let arrival = net.paths[0];
        net.receive(1, arrival, packet_buf(init));
    }
    drop(net.drain());
    net.take_transmits(1)
}

/// More initiations than the limit within a second are answered with cookie replies.
#[test]
fn flood_is_answered_with_cookie_replies() {
    let mut net = net();
    let init = captured_init(&mut net);
    let replies = flood(&mut net, &init, 10);

    // The first copy is answered; the second passes the gate but is a replay.
    assert_eq!(replies[0].data[0], 2, "handshake response");
    assert_eq!(replies.len(), 9, "{replies:?}");
    assert!(replies[1..].iter().all(is_cookie_reply), "{replies:?}");
    assert!(replies.iter().all(|t| t.path == net.paths[0]));
    let rejected = net
        .take_events(1)
        .into_iter()
        .filter(|e| matches!(e, Event::Dropped { .. }))
        .count();
    assert_eq!(rejected, 1, "the replay");
}

/// Under load, the initiator gets a cookie reply from the responder's gate, retries with mac2,
/// passes the gate and the peer's tunnel, and completes the handshake; data flows afterwards.
#[test]
fn handshake_completes_with_a_cookie_under_load() {
    let mut net = net();
    let init = captured_init(&mut net);
    flood(&mut net, &init, 10);
    net.clear_logs();

    // A fresh initiation without mac2 gets a cookie reply, which authenticates nothing.
    net.advance(Duration::from_millis(1));
    net.handshake(0, 1);
    let replies = net.take_transmits(1);
    assert!(
        replies.len() == 1 && is_cookie_reply(&replies[0]),
        "{replies:?}"
    );
    assert_eq!(net.take_events(0), Vec::new(), "the cookie is accepted");
    assert_eq!(net.take_events(1), Vec::new());

    // Still under load: the retry carries the cookie and gets a response.
    net.advance(Duration::from_millis(1));
    net.handshake(0, 1);
    assert!(!net.take_transmits(1).iter().any(is_cookie_reply));
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(handshakes(&net.take_events(1)), 1);

    let packet = net.ping4(0, 1, b"under load");
    assert_eq!(net.take_delivered(1).last().unwrap().1, packet);
    let packet = net.ping4(1, 0, b"and back");
    assert_eq!(net.take_delivered(0).last().unwrap().1, packet);
}

/// After a second the rate limiter resets, and plain handshakes work again.
#[test]
fn limiter_resets_after_a_second() {
    let mut net = net();
    let init = captured_init(&mut net);
    assert!(flood(&mut net, &init, 10).iter().any(is_cookie_reply));
    net.clear_logs();

    net.advance(Duration::from_secs(1));
    net.handshake(0, 1);
    assert!(!net.take_transmits(1).iter().any(is_cookie_reply));
    assert_eq!(handshakes(&net.take_events(0)), 1);
}

/// A cookie reply arriving on a new path is accepted but does not move the peer's path.
#[test]
fn cookie_reply_does_not_roam() {
    let mut net = net();
    let init = captured_init(&mut net);
    flood(&mut net, &init, 10);
    net.clear_logs();

    let elsewhere = Path {
        addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 4500)),
        ..net.paths[1]
    };
    net.set_interceptor(move |d| {
        if d.from == 1 {
            d.arrival = elsewhere;
        }
        Fate::Pass
    });
    net.advance(Duration::from_millis(1));
    net.handshake(0, 1);
    assert!(net.take_transmits(1).iter().all(is_cookie_reply));
    assert_eq!(net.take_events(0), Vec::new());
    let peer = net.peer_id(0, 1);
    assert_eq!(
        net.cores[0].peer_stats(peer).unwrap().path,
        Some(net.paths[1])
    );
}

/// Garbage and truncated datagrams are dropped without a peer, and nothing is sent back.
#[test]
fn garbage_is_dropped() {
    let mut net = net();
    let init = captured_init(&mut net);
    let mut bad_mac = init.clone();
    bad_mac[120] ^= 1;
    let mut data = vec![0u8; 64];
    data[0] = 4;

    for datagram in [
        Vec::new(),
        vec![1, 2, 3],
        vec![0xff; 200],
        init[..100].to_vec(),
        [init.as_slice(), &[0]].concat(),
        bad_mac,
        vec![1; 148],
        vec![2; 92],
        vec![3; 64],
        data,
    ] {
        let arrival = net.paths[0];
        net.receive(1, arrival, packet_buf(&datagram));
        net.pump();
        let events = net.take_events(1);
        assert!(
            matches!(events[..], [Event::Dropped { peer: None, .. }]),
            "{datagram:?}: {events:?}"
        );
        assert_eq!(net.take_transmits(1), Vec::new());
        assert_eq!(net.take_delivered(1), Vec::new());
    }
}

/// A flood above the limit of a peer's own tunnel (10 per second) loads both the gate and the
/// tunnel; the cookie from the gate must still get the retry through the tunnel.
#[test]
fn handshake_completes_with_a_cookie_under_heavy_load() {
    let mut net = Net::with_configs(2, |_| CoreConfig {
        handshake_rate_limit: 20,
        ..CoreConfig::default()
    });
    let init = captured_init(&mut net);
    assert!(flood(&mut net, &init, 30).iter().any(is_cookie_reply));
    net.clear_logs();

    net.advance(Duration::from_millis(1));
    net.handshake(0, 1);
    assert!(net.take_transmits(1).iter().all(is_cookie_reply));
    net.advance(Duration::from_millis(1));
    net.handshake(0, 1);
    assert!(!net.take_transmits(1).iter().any(is_cookie_reply));
    assert_eq!(handshakes(&net.take_events(0)), 1);
}
