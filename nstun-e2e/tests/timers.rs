//! Timers over an in-memory channel transport.
//!
//! The engine schedules the core's timer ticks on tokio's clock, so a paused runtime drives
//! the tick and the periodic stats.
//!
//! Known limitation (Phase 1): the persistent-keepalive interval, rekey after 120 s, session
//! expiry after 540 s (`Event::SessionExpired`) and re-handshake on an established session via
//! `force_handshake` are not tested at engine level. The tunnel timers read boringtun's own
//! clock (boringtun/src/noise/timers.rs), not the engine's tokio clock: nstun-core calls
//! `update_timers` without a time (nstun-core/src/core.rs), and under `--all-features` the
//! `mock-instant` feature of nstun-core (nstun-core/Cargo.toml) freezes that clock, so the
//! TAI64N timestamp of a re-handshake does not advance (boringtun/src/noise/handshake.rs).
//! They are covered at core level by nstun-core/tests/timers.rs. Planned fix (Phase 2): pass
//! the engine's `now` into the tunnel timers, then add the engine-level timer tests here.
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
