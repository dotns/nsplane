//! Per-peer counters: `rx`/`tx` count whole datagrams on the wire (handshakes, keepalives,
//! data), `data_rx`/`data_tx` the plaintext payload.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::time::Duration;

use common::{Net, packet_buf};
use nsplane_core::{ConfigChange, CoreConfig, Event, Output, PeerStats};

const INIT: u64 = 148;
const RESPONSE: u64 = 92;
const KEEPALIVE: u64 = 32;

/// Counters of core `i` for its peer core `j`.
fn stats(net: &Net, i: usize, j: usize) -> PeerStats {
    net.cores[i].peer_stats(net.peer_id(i, j)).unwrap()
}

/// `(rx, tx, data_rx, data_tx)` of core `i` for core `j`.
fn counters(net: &Net, i: usize, j: usize) -> (u64, u64, u64, u64) {
    let s = stats(net, i, j);
    (s.rx, s.tx, s.data_rx, s.data_tx)
}

/// Both ends agree when nothing is lost.
fn assert_agree(net: &Net) {
    let (a, b) = (stats(net, 0, 1), stats(net, 1, 0));
    assert_eq!((a.tx, a.rx), (b.rx, b.tx), "{a:?} {b:?}");
    assert_eq!(
        (a.data_tx, a.data_rx),
        (b.data_rx, b.data_tx),
        "{a:?} {b:?}"
    );
}

#[test]
fn handshakes_keepalives_and_data_count_on_the_wire() {
    let mut net = Net::new(2);
    assert_eq!(counters(&net, 0, 1), (0, 0, 0, 0));
    assert_eq!(counters(&net, 1, 0), (0, 0, 0, 0));

    // The initiator confirms the handshake with a keepalive.
    net.handshake(0, 1);
    assert_eq!(counters(&net, 0, 1), (RESPONSE, INIT + KEEPALIVE, 0, 0));
    assert_eq!(counters(&net, 1, 0), (INIT + KEEPALIVE, RESPONSE, 0, 0));
    assert_agree(&net);

    // A persistent keepalive.
    net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer: net.public_key(1),
            interval: Some(1),
        },
    );
    net.clear_logs();
    net.run_for(Duration::from_secs(1));
    let sent = net.take_transmits(0);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].data.len() as u64, KEEPALIVE);
    assert_eq!(counters(&net, 0, 1), (RESPONSE, INIT + 2 * KEEPALIVE, 0, 0));
    assert_agree(&net);

    // 33 bytes of IP packet are padded to 48 and sealed behind a 16-byte header and tag.
    let (rx, tx, ..) = counters(&net, 0, 1);
    let packet = net.ping4(0, 1, b"hello");
    let n = packet.len() as u64;
    assert_eq!(n, 33);
    assert_eq!(counters(&net, 0, 1), (rx, tx + KEEPALIVE + 48, 0, n));
    assert_eq!(counters(&net, 1, 0), (tx + KEEPALIVE + 48, rx, n, 0));
    assert_agree(&net);
}

#[test]
fn packets_queued_behind_a_handshake_count_when_sent() {
    let mut net = Net::new(2);
    let packet = net.ping4(0, 1, b"queued");
    let n = packet.len() as u64;
    let sealed = KEEPALIVE + n.next_multiple_of(16);

    // The initiator confirms the handshake with a keepalive, then flushes the queued packet.
    let a = counters(&net, 0, 1);
    assert_eq!(a, (RESPONSE, INIT + KEEPALIVE + sealed, 0, n));
    assert_eq!(net.take_delivered(1).len(), 1);
    assert_agree(&net);
}

#[test]
fn peer_stats_events_report_the_counters() {
    let mut net = Net::with_configs(2, |i| CoreConfig {
        stats_interval: (i == 0).then_some(Duration::from_secs(1)),
        ..CoreConfig::default()
    });
    net.ping4(0, 1, b"out");
    net.ping4(1, 0, b"in");
    net.clear_logs();
    net.run_for(Duration::from_secs(1));

    let expected = stats(&net, 0, 1);
    let events = net.take_events(0);
    let [
        Event::PeerStats {
            rx,
            tx,
            data_rx,
            data_tx,
            ..
        },
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(
        (*rx, *tx, *data_rx, *data_tx),
        (expected.rx, expected.tx, expected.data_rx, expected.data_tx)
    );
    assert!(*data_rx > 0 && *data_tx > 0 && *rx > *data_rx && *tx > *data_tx);
}

#[test]
fn cookie_replies_under_load_change_no_counter() {
    let mut net = Net::with_configs(2, |_| CoreConfig {
        handshake_rate_limit: 2,
        ..CoreConfig::default()
    });
    let peer = net.peer_id(0, 1);
    net.cores[0].force_handshake(peer, None, net.now);
    let Some(Output::Transmit { data, .. }) = net.cores[0].poll_output() else {
        panic!("expected an initiation");
    };
    let init = data.as_packet().to_vec();
    assert_eq!(counters(&net, 0, 1), (0, INIT, 0, 0));

    // The first copy is answered; the replays are rejected or answered with cookie replies.
    let arrival = net.paths[0];
    net.receive(1, arrival, packet_buf(&init));
    drop(net.drain());
    let before = counters(&net, 1, 0);
    assert_eq!(before, (INIT, RESPONSE, 0, 0));
    for _ in 0..8 {
        net.receive(1, arrival, packet_buf(&init));
    }
    drop(net.drain());
    let replies: Vec<_> = net.take_transmits(1).into_iter().skip(1).collect();
    assert_eq!(replies.len(), 7, "{replies:?}");
    assert!(
        replies.iter().all(|t| t.data.len() == 64 && t.data[0] == 3),
        "{replies:?}"
    );
    assert_eq!(counters(&net, 1, 0), before);

    // Nor does the initiator count a cookie reply it accepts.
    let arrival = net.paths[1];
    net.receive(0, arrival, packet_buf(&replies[0].data));
    drop(net.drain());
    assert_eq!(counters(&net, 0, 1), (0, INIT, 0, 0));
}
