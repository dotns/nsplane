//! Suspend and resume over an in-memory channel transport, on a paused clock.
//!
//! While an engine is suspended no I/O runs and no timer fires, so packets wait and the
//! clock can jump past a session's lifetime; resuming runs the timers once and the tunnel
//! carries on, with a new handshake only when the session expired meanwhile.

use std::time::Duration;

use nsplane::{ChannelTransport, Event, PeerId};
use nsplane_e2e::{Family, Node, Options, TestResult, channel_pair, introduce, transfer};
use tokio::time::advance;

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

/// Whether `event` reports a suspension or a resume.
const fn is_suspension(event: &Event) -> bool {
    matches!(event, Event::Suspended | Event::Resumed)
}

/// Whether `event` reports a completed handshake with `peer`.
fn handshake_completed(event: &Event, peer: PeerId) -> bool {
    matches!(event, Event::HandshakeCompleted { peer: p, .. } if *p == peer)
}

/// Whether `event` reports the expiry of the sessions with `peer`.
fn session_expired(event: &Event, peer: PeerId) -> bool {
    matches!(event, Event::SessionExpired { peer: p } if *p == peer)
}

/// The datagrams `node` has received from `peer`.
async fn received(node: &Node<ChannelTransport>, peer: PeerId) -> TestResult<u64> {
    let stats = node.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
    Ok(stats.rx)
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn suspend_and_resume_publish_one_event_each() -> TestResult {
    let (a, _b) = connected().await?;
    let mut events = a.subscribe().await?;

    a.handle.suspend().await?;
    a.handle.suspend().await?;
    a.handle.resume().await?;
    a.handle.resume().await?;
    assert!(matches!(
        events.expect(is_suspension).await?,
        Event::Suspended
    ));
    assert!(matches!(
        events.expect(is_suspension).await?,
        Event::Resumed
    ));
    events.expect_none(is_suspension).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn no_traffic_flows_while_suspended() -> TestResult {
    let (a, mut b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;

    // The sender is suspended: the packet does not even leave it.
    let rx = received(&b, peer_a).await?;
    a.handle.suspend().await?;
    let packet = a.packet_to(&b, Family::V4, b"suspended sender");
    a.send(&packet).await?;
    b.expect_no_delivery().await?;
    assert_eq!(received(&b, peer_a).await?, rx);
    a.handle.resume().await?;
    assert_eq!(b.expect_delivery().await?.1, packet);

    // The receiver is suspended: nothing reaches its core or its sink.
    let rx = received(&b, peer_a).await?;
    b.handle.suspend().await?;
    let packet = a.packet_to(&b, Family::V6, b"suspended receiver");
    a.send(&packet).await?;
    b.expect_no_delivery().await?;
    assert_eq!(received(&b, peer_a).await?, rx);
    b.handle.resume().await?;
    assert_eq!(b.expect_delivery().await?.1, packet);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sessions_survive_a_short_suspend() -> TestResult {
    let (mut a, mut b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;

    a.handle.suspend().await?;
    b.handle.suspend().await?;
    // Shorter than `KEEPALIVE_TIMEOUT` (10 s): a longer silence after the last data is a
    // reason for a new handshake even without a suspension.
    advance(Duration::from_secs(5)).await;
    a.handle.resume().await?;
    b.handle.resume().await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;
    a_events
        .expect_none(|e| handshake_completed(e, peer_b))
        .await?;
    b_events
        .expect_none(|e| handshake_completed(e, peer_a))
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_session_that_expired_while_suspended_rehandshakes_on_resume() -> TestResult {
    let (mut a, mut b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;

    a.handle.suspend().await?;
    b.handle.suspend().await?;
    // No timer fires while suspended, however far the clock jumps.
    advance(SESSION_EXPIRY + Duration::from_secs(1)).await;
    a_events.expect_none(|e| session_expired(e, peer_b)).await?;
    a.handle.resume().await?;
    b.handle.resume().await?;
    a_events.expect(|e| session_expired(e, peer_b)).await?;
    b_events.expect(|e| session_expired(e, peer_a)).await?;

    transfer(&a, &mut b, Family::V4, 64).await?;
    a_events.expect(|e| handshake_completed(e, peer_b)).await?;
    b_events.expect(|e| handshake_completed(e, peer_a)).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;
    Ok(())
}
