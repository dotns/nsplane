//! Timers over an in-memory channel transport.
//!
//! The engine schedules the core's timer ticks on tokio's clock, so a paused runtime drives
//! the tick and the periodic stats. The tunnels' own timers (keepalive and rekey intervals,
//! session expiry) read boringtun's monotonic clock instead, which tokio time does not move:
//! the interval test below waits in real time.
//!
//! Keepalives carry no payload and are not counted in the peer's byte counters, so the
//! receiving side is moved to a path that leads nowhere first: a keepalive from the real
//! address is then reported as `Event::Authenticated`.

use std::net::SocketAddr;
use std::time::Duration;

use nstun::{ChannelTransport, Event, Path, PeerId};
use nstun_e2e::{Events, Family, Node, Options, TestResult, channel_pair, introduce, transfer};
use tokio::time::advance;

/// The interval of the core's timer tick.
const TICK: Duration = Duration::from_millis(250);

/// Two linked nodes that completed a handshake with traffic in both directions.
async fn connected() -> TestResult<(Node<ChannelTransport>, Node<ChannelTransport>)> {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    Ok((a, b))
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

#[tokio::test]
async fn persistent_keepalive_repeats_after_its_interval() -> TestResult {
    let (a, b) = connected().await?;
    let peer_a = b.peer_of(&a).await?;
    let mut events = b.subscribe().await?;

    // The first keepalive goes out on the next tick, the second one after a second of
    // silence on boringtun's clock, which only real time moves.
    let real = forget_path(&a, &b).await?;
    a.handle.set_keepalive(b.public(), Some(1)).await?;
    expect_message(&mut events, peer_a, real).await?;
    forget_path(&a, &b).await?;
    expect_message(&mut events, peer_a, real).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stats_follow_the_paused_clock() -> TestResult {
    let interval = Duration::from_secs(60);
    let (a, b) = channel_pair(Options {
        stats_interval: Some(interval),
    });
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut events = a.subscribe().await?;
    let stats = |e: &Event| matches!(e, Event::PeerStats { peer, .. } if *peer == peer_b);

    advance(interval - Duration::from_secs(1)).await;
    events.expect_none(stats).await?;
    advance(Duration::from_secs(1)).await;
    events.expect(stats).await?;
    Ok(())
}
