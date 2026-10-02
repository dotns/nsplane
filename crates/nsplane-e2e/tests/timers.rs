//! Timers over an in-memory channel transport.
//!
//! The engine schedules the core's timer ticks on tokio's clock, so a paused runtime drives
//! the tick and the periodic stats.
//!
//! Every tunnel timer runs on the engine's clock too, so these tests cover the persistent
//! keepalive interval, rekey after `REKEY_AFTER_TIME` (120 s), session expiry after three times
//! `REJECT_AFTER_TIME` (540 s) and re-handshakes via `force_handshake`, also two within one
//! tick. Long waits advance the clock one tick at a time, so the engines run every tick in
//! between as they would in real time.
//!
//! Keepalives are observed as `Event::Authenticated`, which marks each one as it arrives; the
//! peer's wire counters see them too, but only at the periodic stats. The receiving side is
//! moved to a path that leads nowhere first, so a keepalive from the real address is reported.

use std::net::SocketAddr;
use std::time::Duration;

use nsplane::{ChannelTransport, Event, Path, PeerId};
use nsplane_e2e::{Events, Family, Node, Options, TestResult, channel_pair, introduce, transfer};
use tokio::time::{Instant, advance};

/// The interval of the core's timer tick.
const TICK: Duration = Duration::from_millis(250);
/// Age of a session at which its initiator starts a new handshake when sending.
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// Age of the last session at which the peer's sessions expire: three times
/// `REJECT_AFTER_TIME` (180 s).
const SESSION_EXPIRY: Duration = Duration::from_mins(9);

/// Two linked nodes that completed a handshake with traffic in both directions.
async fn connected() -> TestResult<(Node<ChannelTransport>, Node<ChannelTransport>)> {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    Ok((a, b))
}

/// Advances the paused clock by `duration` one tick at a time.
async fn run_for(duration: Duration) {
    let mut left = duration;
    while !left.is_zero() {
        let step = left.min(TICK);
        advance(step).await;
        left = left.saturating_sub(step);
    }
}

/// Whether `event` reports a completed handshake with `peer`.
fn handshake_completed(event: &Event, peer: PeerId) -> bool {
    matches!(event, Event::HandshakeCompleted { peer: p, .. } if *p == peer)
}

/// Whether `event` reports the expiry of the sessions with `peer`.
fn session_expired(event: &Event, peer: PeerId) -> bool {
    matches!(event, Event::SessionExpired { peer: p } if *p == peer)
}

/// Moves `b`'s path to `a` away, so the next message from `a` is reported as
/// `Event::Authenticated` from `a`'s real path, which this returns.
async fn forget_path(a: &Node<ChannelTransport>, b: &Node<ChannelTransport>) -> TestResult<Path> {
    let real = Path {
        transport: b.path.transport,
        ..a.path
    };
    let nowhere = Path {
        addr: SocketAddr::from(([192, 0, 2, 99], 9)),
        ..real
    };
    b.handle.set_path(a.public(), nowhere).await?;
    Ok(real)
}

/// Waits for a message from `peer` on `path`.
async fn expect_message(events: &mut Events, peer: PeerId, path: Path) -> TestResult {
    events
        .expect(
            |e| matches!(e, Event::Authenticated { peer: p, from } if *p == peer && *from == path),
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn enabling_persistent_keepalive_sends_one_on_the_next_tick() -> TestResult {
    let (a, b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let data_rx = b
        .handle
        .peer_stats(peer_a)
        .await?
        .ok_or("unknown peer")?
        .data_rx;
    let real = forget_path(&a, &b).await?;
    let mut events = b.subscribe().await?;

    a.handle.set_keepalive(b.public(), Some(25)).await?;
    advance(TICK).await;
    expect_message(&mut events, peer_a, real).await?;
    // A keepalive carries no payload.
    let stats = b.handle.peer_stats(peer_a).await?.ok_or("unknown peer")?;
    assert_eq!(stats.data_rx, data_rx);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stats_follow_the_paused_clock() -> TestResult {
    let before = Duration::from_secs(59);
    let interval = before + Duration::from_secs(1);
    let (a, b) = channel_pair(Options {
        stats_interval: Some(interval),
    });
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut events = a.subscribe().await?;
    let stats = |e: &Event| matches!(e, Event::PeerStats { peer, .. } if *peer == peer_b);

    advance(before).await;
    events.expect_none(stats).await?;
    advance(Duration::from_secs(1)).await;
    events.expect(stats).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn persistent_keepalives_follow_the_interval() -> TestResult {
    let interval = Duration::from_secs(25);
    let (a, b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let real = forget_path(&a, &b).await?;
    let mut events = b.subscribe().await?;

    a.handle.set_keepalive(b.public(), Some(25)).await?;
    advance(TICK).await;
    expect_message(&mut events, peer_a, real).await?;
    let mut last = Instant::now();
    for _ in 0..3 {
        forget_path(&a, &b).await?;
        run_for(interval.saturating_sub(Duration::from_secs(1))).await;
        events
            .expect_none(|e| matches!(e, Event::Authenticated { peer, .. } if *peer == peer_a))
            .await?;
        expect_message(&mut events, peer_a, real).await?;
        let gap = last.elapsed();
        assert!(
            gap >= interval && gap <= interval + TICK,
            "keepalive {gap:?} after the previous one"
        );
        last = Instant::now();
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sending_after_rekey_after_time_starts_a_new_handshake() -> TestResult {
    let (mut a, mut b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;

    run_for(REKEY_AFTER_TIME.saturating_sub(Duration::from_secs(1))).await;
    transfer(&a, &mut b, Family::V4, 64).await?;
    a_events
        .expect_none(|e| handshake_completed(e, peer_b))
        .await?;
    run_for(Duration::from_secs(1)).await;
    transfer(&a, &mut b, Family::V4, 64).await?;
    a_events
        .expect(|e| {
            matches!(e, Event::HandshakeCompleted { peer, rtt: Some(_), .. } if *peer == peer_b)
        })
        .await?;
    b_events.expect(|e| handshake_completed(e, peer_a)).await?;
    transfer(&a, &mut b, Family::V6, 64).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn idle_sessions_expire_after_three_reject_after_times() -> TestResult {
    let (a, b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;

    run_for(SESSION_EXPIRY.saturating_sub(Duration::from_secs(1))).await;
    a_events.expect_none(|e| session_expired(e, peer_b)).await?;
    b_events.expect_none(|e| session_expired(e, peer_a)).await?;
    run_for(Duration::from_secs(1)).await;
    a_events.expect(|e| session_expired(e, peer_b)).await?;
    b_events.expect(|e| session_expired(e, peer_a)).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn force_handshake_rekeys_an_established_session() -> TestResult {
    let (mut a, mut b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;

    run_for(Duration::from_secs(1)).await;
    a.handle.force_handshake(peer_b, None).await?;
    a_events
        .expect(|e| {
            matches!(e, Event::HandshakeCompleted { peer, rtt: Some(_), .. } if *peer == peer_b)
        })
        .await?;
    // The responder counts the handshake when the initiator's keepalive confirms it.
    b_events.expect(|e| handshake_completed(e, peer_a)).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn two_handshakes_within_one_tick_are_both_reported() -> TestResult {
    let (mut a, mut b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;

    let start = Instant::now();
    for _ in 0..2 {
        a.handle.force_handshake(peer_b, None).await?;
        a_events.expect(|e| handshake_completed(e, peer_b)).await?;
        b_events.expect(|e| handshake_completed(e, peer_a)).await?;
    }
    // The paused clock stood still, so no tick ran between the two handshakes.
    assert_eq!(start.elapsed(), Duration::ZERO);
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    Ok(())
}
