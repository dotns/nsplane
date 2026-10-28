//! The WireGuard timers driven through two cores on the fake clock: rekeying, handshake
//! retries, keepalives, session expiry and the timer schedule.
//!
//! `rekey_after_messages_starts_a_handshake` is not ported: the rekey message count is 2^60,
//! which no test can send through a core, and the core offers no way to wear a session out.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

mod common;

use std::time::Duration;

use common::{Fate, Net, Sent, default_config};
use nsplane_core::{ConfigChange, CoreConfig, Event, ExpiryCause, PeerId};

const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(250);

fn inits(transmits: &[Sent]) -> usize {
    transmits
        .iter()
        .filter(|t| t.data.len() == 148 && t.data[0] == 1)
        .count()
}

fn keepalives(transmits: &[Sent]) -> usize {
    transmits
        .iter()
        .filter(|t| t.data.len() == 32 && t.data[0] == 4)
        .count()
}

fn handshakes(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::HandshakeCompleted { .. }))
        .count()
}

fn expiries(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::SessionExpired { .. }))
        .count()
}

/// Port of nsplane-noise `noise::tests::full_handshake_plus_timers`.
#[test]
fn full_handshake_plus_timers() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();

    // Nothing is due right after the handshake.
    net.run_for(Duration::from_secs(1));
    for i in 0..2 {
        assert_eq!(net.take_transmits(i), Vec::new());
        assert_eq!(net.take_events(i), Vec::new());
    }
}

/// Port of nsplane-noise `noise::tests::new_handshake_after_two_mins`: the initiator rekeys once
/// its session is `REKEY_AFTER_TIME` old and it sent data on it.
#[test]
fn new_handshake_after_two_mins() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.advance(Duration::from_secs(1));
    net.ping4(0, 1, b"keep the session busy");
    net.clear_logs();

    // The session is established at 0 s; the data went out at 1 s.
    net.run_for(REKEY_AFTER_TIME.saturating_sub(Duration::from_secs(2)));
    assert_eq!(inits(&net.take_transmits(0)), 0);
    assert_eq!(handshakes(&net.take_events(0)), 0);

    net.run_for(Duration::from_secs(2));
    assert_eq!(inits(&net.take_transmits(0)), 1);
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(handshakes(&net.take_events(1)), 1);
    let packet = net.ping4(0, 1, b"on the new session");
    assert_eq!(net.take_delivered(1).last().unwrap().1, packet);
}

/// Port of nsplane-noise `noise::tests::handshake_no_resp_rekey_timeout`: an unanswered initiation
/// is retried after `REKEY_TIMEOUT` plus up to 333 ms of jitter.
#[test]
fn handshake_no_resp_rekey_timeout() {
    let mut net = Net::new(2);
    net.set_interceptor(|_| Fate::Drop);
    net.handshake(0, 1);
    assert_eq!(inits(&net.take_transmits(0)), 1);

    net.run_for(REKEY_TIMEOUT.saturating_sub(TICK));
    assert_eq!(inits(&net.take_transmits(0)), 0);
    net.run_for(Duration::from_secs(1));
    assert_eq!(inits(&net.take_transmits(0)), 1);
}

/// The initiator keeps retrying for `REKEY_ATTEMPT_TIME`, then gives up and reports the
/// expiry once, also for a peer that was never up; data afterwards starts a new handshake.
#[test]
fn handshake_gives_up_after_rekey_attempt_time() {
    let mut net = Net::new(2);
    net.set_interceptor(|_| Fate::Drop);
    let peer = net.peer_id(0, 1);
    net.handshake(0, 1);

    net.run_for(REKEY_ATTEMPT_TIME.saturating_sub(TICK));
    let retries = inits(&net.take_transmits(0));
    assert!((15..=18).contains(&retries), "{retries} initiations");
    assert_eq!(expiries(&net.take_events(0)), 0);

    net.run_for(Duration::from_secs(1));
    assert_eq!(
        net.take_events(0),
        [Event::SessionExpired {
            peer,
            cause: ExpiryCause::HandshakeTimeout
        }],
        "reported once"
    );
    assert_eq!(expirations(&net, 0, 1), 1);
    net.run_for(Duration::from_secs(30));
    assert_eq!(net.take_transmits(0), Vec::new(), "no more retries");
    assert_eq!(net.take_events(0), Vec::new());

    net.clear_interceptor();
    let packet = net.ping4(0, 1, b"try again");
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(
        net.take_delivered(1)
            .into_iter()
            .map(|(_, p)| p)
            .collect::<Vec<_>>(),
        [packet]
    );
}

/// Data is answered by a passive keepalive `KEEPALIVE_TIMEOUT` later, and only once.
#[test]
fn passive_keepalive_after_received_data() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.ping4(0, 1, b"ping");
    net.clear_logs();

    net.run_for(KEEPALIVE_TIMEOUT.saturating_sub(TICK));
    assert_eq!(net.take_transmits(1), Vec::new());
    net.run_for(Duration::from_millis(500));
    let transmits = net.take_transmits(1);
    assert_eq!((transmits.len(), keepalives(&transmits)), (1, 1));

    net.run_for(Duration::from_secs(30));
    assert_eq!(net.take_transmits(0), Vec::new());
    assert_eq!(net.take_transmits(1), Vec::new());
    assert_eq!(net.take_delivered(0), Vec::new());
}

/// A persistent keepalive goes out as soon as it is enabled, then whenever the tunnel was
/// idle for the interval.
#[test]
fn persistent_keepalive_when_idle() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();
    let peer = net.public_key(1);
    net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer,
            interval: Some(5),
        },
    );

    net.advance(TICK);
    assert_eq!(keepalives(&net.take_transmits(0)), 1);
    net.run_for(Duration::from_secs(20));
    let transmits = net.take_transmits(0);
    assert_eq!((transmits.len(), keepalives(&transmits)), (4, 4));
    assert_eq!(
        net.take_transmits(1),
        Vec::new(),
        "keepalives carry no data"
    );
}

/// No keepalive goes out while data flows in both directions.
#[test]
fn persistent_keepalive_not_sent_while_traffic_flows() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    let peer = net.public_key(1);
    net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer,
            interval: Some(5),
        },
    );
    net.advance(TICK);
    net.clear_logs();

    for _ in 0..20 {
        net.ping4(0, 1, b"busy");
        net.ping4(1, 0, b"busy");
        net.run_for(Duration::from_secs(1));
    }
    for i in 0..2 {
        let transmits = net.take_transmits(i);
        assert_eq!(transmits.len(), 20);
        assert_eq!(keepalives(&transmits), 0);
    }
}

/// Port of nsplane-noise `noise::tests::persistent_keepalive_can_be_changed`, through
/// `ConfigChange::SetKeepalive`.
#[test]
fn keepalive_interval_change() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    let (peer, id) = (net.public_key(1), net.peer_id(0, 1));
    let set = |net: &mut Net, interval| {
        net.configure(0, ConfigChange::SetKeepalive { peer, interval });
        net.advance(TICK);
        net.clear_logs();
    };

    set(&mut net, Some(5));
    net.run_for(Duration::from_secs(20));
    assert_eq!(keepalives(&net.take_transmits(0)), 4);

    set(&mut net, Some(10));
    assert_eq!(
        net.cores[0].peer_stats(id).unwrap().persistent_keepalive,
        Some(10)
    );
    net.run_for(Duration::from_secs(20));
    assert_eq!(keepalives(&net.take_transmits(0)), 2);

    set(&mut net, None);
    assert_eq!(
        net.cores[0].peer_stats(id).unwrap().persistent_keepalive,
        None
    );
    net.run_for(Duration::from_secs(20));
    assert_eq!(net.take_transmits(0), Vec::new());
}

/// Without a new handshake for `REJECT_AFTER_TIME * 3`, the sessions expire, once per expiry.
/// Data afterwards starts a new handshake and is delivered once it completes.
#[test]
fn session_expires_after_reject_after_time_x3() {
    let mut net = Net::new(2);
    let (a_to_b, b_to_a) = (net.peer_id(0, 1), net.peer_id(1, 0));
    net.ping4(0, 1, b"hello");
    net.clear_logs();

    net.run_for((REJECT_AFTER_TIME * 3).saturating_sub(TICK));
    assert_eq!(expiries(&net.take_events(0)), 0);
    assert_eq!(expiries(&net.take_events(1)), 0);
    net.run_for(Duration::from_secs(1));
    assert_eq!(net.take_events(0), [session_age(a_to_b)]);
    assert_eq!(net.take_events(1), [session_age(b_to_a)]);
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.take_events(0), Vec::new(), "reported once");
    assert_eq!(net.take_events(1), Vec::new());

    // The packet waits for the new handshake.
    let packet = net.ping4(0, 1, b"after the expiry");
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(net.take_delivered(1), [(b_to_a, packet)]);

    // The next expiry is reported again.
    net.clear_logs();
    net.run_for(REJECT_AFTER_TIME * 3 + Duration::from_secs(1));
    assert_eq!(net.take_events(0), [session_age(a_to_b)]);
    assert_eq!(expirations(&net, 0, 1), 2);
}

/// `Event::SessionExpired` of `peer` for [`ExpiryCause::SessionAge`].
const fn session_age(peer: PeerId) -> Event {
    Event::SessionExpired {
        peer,
        cause: ExpiryCause::SessionAge,
    }
}

/// `PeerStats::expirations` of core `j` as a peer of core `i`.
fn expirations(net: &Net, i: usize, j: usize) -> u64 {
    net.cores[i]
        .peer_stats(net.peer_id(i, j))
        .unwrap()
        .expirations
}

/// A peer that never completed a handshake reports no expiry when its idle timer runs out,
/// and counts none.
#[test]
fn a_never_contacted_peer_reports_no_expiry() {
    let mut net = Net::new(2);
    net.clear_logs();

    net.run_for(REJECT_AFTER_TIME * 3 + Duration::from_secs(1));
    for (i, j) in [(0, 1), (1, 0)] {
        assert_eq!(net.take_events(i), Vec::new());
        assert_eq!(expirations(&net, i, j), 0);
    }
    net.run_for(Duration::from_secs(600));
    for (i, j) in [(0, 1), (1, 0)] {
        assert_eq!(net.take_events(i), Vec::new());
        assert_eq!(net.take_transmits(i), Vec::new());
        assert_eq!(expirations(&net, i, j), 0);
    }
}

/// A peer that was never up and whose idle expiry was not reported still reports that its
/// initiations went unanswered, once.
#[test]
fn a_never_up_peer_reports_handshake_timeout_after_an_unreported_idle_expiry() {
    let mut net = Net::new(2);
    let peer = net.peer_id(0, 1);
    net.run_for(REJECT_AFTER_TIME * 3 + Duration::from_secs(1));
    net.clear_logs();

    net.set_interceptor(|_| Fate::Drop);
    net.ping4(0, 1, b"nobody answers");
    net.run_for(REKEY_ATTEMPT_TIME.saturating_sub(TICK));
    assert_eq!(expiries(&net.take_events(0)), 0);
    net.run_for(Duration::from_secs(1));
    assert_eq!(
        net.take_events(0),
        [Event::SessionExpired {
            peer,
            cause: ExpiryCause::HandshakeTimeout
        }]
    );
    net.run_for(Duration::from_secs(30));
    assert_eq!(net.take_events(0), Vec::new(), "reported once");
    assert_eq!(expirations(&net, 0, 1), 1);
}

/// `expirations` equals the number of `Event::SessionExpired` reported, over one expiry of
/// each cause, and a completed handshake leaves it.
#[test]
fn expirations_count_the_reported_expiries() {
    let mut net = Net::new(2);
    let peer = net.peer_id(0, 1);
    net.ping4(0, 1, b"up");
    net.clear_logs();

    net.run_for(REJECT_AFTER_TIME * 3 + Duration::from_secs(1));
    assert_eq!(net.take_events(0), [session_age(peer)]);
    assert_eq!(expirations(&net, 0, 1), 1);
    assert_eq!(expirations(&net, 1, 0), 1);

    net.set_interceptor(|_| Fate::Drop);
    net.ping4(0, 1, b"nobody answers");
    net.run_for(REKEY_ATTEMPT_TIME + Duration::from_secs(1));
    assert_eq!(
        net.take_events(0),
        [Event::SessionExpired {
            peer,
            cause: ExpiryCause::HandshakeTimeout
        }]
    );
    assert_eq!(expirations(&net, 0, 1), 2);
    assert_eq!(expirations(&net, 1, 0), 1, "the responder saw nothing");

    net.clear_interceptor();
    net.ping4(0, 1, b"up again");
    assert_eq!(handshakes(&net.take_events(0)), 1);
    assert_eq!(expirations(&net, 0, 1), 2);
    assert_eq!(expirations(&net, 1, 0), 1);
}

/// The periodic `Event::PeerStats` of the tick that expires a peer follows its
/// `Event::SessionExpired` and already counts it; every one counts the expiries before it.
#[test]
fn peer_stats_after_an_expiry_count_it() {
    let mut net = Net::with_configs(2, |i| CoreConfig {
        stats_interval: Some(TICK),
        ..default_config(i)
    });
    let peer = net.peer_id(0, 1);
    net.ping4(0, 1, b"up");
    net.clear_logs();

    net.run_for(REJECT_AFTER_TIME * 3 + Duration::from_secs(1));
    let events = net.take_events(0);
    let expired = events.iter().position(|e| *e == session_age(peer)).unwrap();
    assert!(
        matches!(events[expired + 1], Event::PeerStats { peer: p, expirations: 1, .. } if p == peer),
        "{:?}",
        &events[expired..]
    );
    let mut reported = 0;
    for event in &events {
        match *event {
            Event::SessionExpired { .. } => reported += 1,
            Event::PeerStats { expirations, .. } => assert_eq!(expirations, reported),
            _ => {}
        }
    }
    assert_eq!(reported, 1);
}

/// The timers tick every 250 ms; `poll_timeout` moves forward only, and `handle_timeout`
/// before the deadline does nothing.
#[test]
fn poll_timeout_cadence() {
    let mut net = Net::new(2);
    net.handshake(0, 1);
    net.clear_logs();
    let deadline = net.cores[0].poll_timeout().unwrap();
    assert!(deadline > net.now && deadline - net.now <= TICK);

    // A keepalive is due on the next tick, but not before it.
    let peer = net.public_key(1);
    net.configure(
        0,
        ConfigChange::SetKeepalive {
            peer,
            interval: Some(25),
        },
    );
    net.cores[0].handle_timeout(deadline.checked_sub(Duration::from_millis(1)).unwrap());
    assert!(net.cores[0].poll_output().is_none());
    assert_eq!(net.cores[0].poll_timeout(), Some(deadline));

    let mut previous = deadline;
    net.run_for(Duration::from_secs(2));
    let next = net.cores[0].poll_timeout().unwrap();
    assert_eq!(next, net.now + TICK);
    assert!(next > previous);
    assert_eq!(keepalives(&net.take_transmits(0)), 1);

    // Each tick schedules the next one 250 ms later, even when called late.
    for late in [0, 100, 1000] {
        previous = net.cores[0].poll_timeout().unwrap();
        let now = previous + Duration::from_millis(late);
        net.advance(now - net.now);
        let next = net.cores[0].poll_timeout().unwrap();
        assert!(next > previous);
        assert_eq!(next, now + TICK);
    }
}
