//! The unanswered handshake counters over an in-memory channel transport, on the paused clock.
//!
//! A completed handshake leaves both counters at 0. Once the initiator's path to its peer leads
//! nowhere, every retry after `REKEY_TIMEOUT` (5 s plus up to 333 ms of jitter, run at the next
//! 250 ms tick) counts the initiation before it as unanswered on the initiator only.

use std::net::SocketAddr;
use std::time::Duration;

use nsplane::Path;
use nsplane_e2e::{Family, Options, TestResult, channel_pair, introduce, transfer};
use tokio::time::advance;

/// The interval of the core's timer tick.
const TICK: Duration = Duration::from_millis(250);

/// Advances the paused clock by `duration` one tick at a time.
async fn run_for(duration: Duration) {
    let mut left = duration;
    while !left.is_zero() {
        let step = left.min(TICK);
        advance(step).await;
        left = left.saturating_sub(step);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retries_without_an_answer_count_on_the_initiator() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    let peer_a = b.peer_of(&a).await?;
    let peer_b = a.peer_of(&b).await?;
    assert_eq!(a.handle.unanswered_handshakes(peer_b).await?, Some(0));
    assert_eq!(b.handle.unanswered_handshakes(peer_a).await?, Some(0));
    assert_eq!(a.handle.total_unanswered_handshakes().await?, 0);
    assert_eq!(b.handle.total_unanswered_handshakes().await?, 0);

    // Cut `b` off: `a`'s initiations go to an address nobody listens on.
    let nowhere = Path {
        transport: a.path.transport,
        addr: SocketAddr::from(([192, 0, 2, 99], 9)),
        ..b.path
    };
    a.handle.set_path(b.public(), nowhere).await?;
    a.handle.force_handshake(peer_b, None).await?;
    assert_eq!(a.handle.unanswered_handshakes(peer_b).await?, Some(0));

    // Retries at about 5.25-5.6 s and 10.5-11.2 s; the third is not due before 15 s.
    run_for(Duration::from_secs(12)).await;
    assert_eq!(a.handle.unanswered_handshakes(peer_b).await?, Some(2));
    assert_eq!(a.handle.total_unanswered_handshakes().await?, 2);
    assert_eq!(b.handle.unanswered_handshakes(peer_a).await?, Some(0));
    assert_eq!(b.handle.total_unanswered_handshakes().await?, 0);
    Ok(())
}
