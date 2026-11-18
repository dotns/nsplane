//! Bulk TCP through two netstacks over a link with jitter: every message takes a delay
//! that varies from one to the next, so messages overtake each other. Nothing is lost.
//!
//! A sender that takes each overtaken segment for a lost one resends it and halves its
//! window every time. The ignored `report` test prints the transfer times and segment
//! counts; run it in release:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test netstack_jitter -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nsplane_e2e::bulk::bulk_tcp;
use nsplane_e2e::{JitterTransport, StackNode, TestResult, stack_pair_over};
use nsplane_netstack::DEFAULT_MTU;

/// Bytes sent per transfer.
const BULK: usize = 4 << 20;
/// Full-size segments [`BULK`] bytes need at the default MTU, rounded up: a segment
/// carries at least 1300 bytes, so about 190 of them are room for retransmissions.
const SEGMENTS: u64 = (BULK as u64).div_ceil(1300);
/// Upper bound for the asserted transfer: well under a second when overtaken segments are
/// not taken for losses.
const BOUND: Duration = Duration::from_secs(10);
/// Upper bound for a transfer in the `report` test.
const REPORT_LIMIT: Duration = Duration::from_secs(120);

/// Two stack nodes over a link that delays each direction by `delay` to `delay + jitter`,
/// and the count of full-size data messages put on the link.
async fn jitter_pair(
    delay: Duration,
    jitter: Duration,
) -> TestResult<(StackNode, StackNode, Arc<AtomicU64>)> {
    let sent = Arc::new(AtomicU64::new(0));
    let (a, b) = stack_pair_over(
        DEFAULT_MTU,
        |link| JitterTransport::new(link, delay, jitter, Arc::clone(&sent)),
        |builder| builder,
    )
    .await?;
    Ok((a, b, sent))
}

/// [`BULK`] bytes over a link of 10 to 14 ms complete within [`BOUND`] with at most
/// [`SEGMENTS`] full-size segments sent.
#[tokio::test]
async fn bulk_tcp_over_a_link_with_jitter() -> TestResult {
    let (a, b, sent) = jitter_pair(Duration::from_millis(10), Duration::from_millis(4)).await?;
    bulk_tcp(&b, &a, BULK, BOUND).await?;
    let sent = sent.load(Ordering::Relaxed);
    assert!(
        sent <= SEGMENTS,
        "{sent} full-size segments sent, {SEGMENTS} allowed"
    );
    Ok(())
}

/// Transfer time and full-size segments sent per delay and jitter.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn report() -> TestResult {
    for (delay, jitter) in [(10, 0), (10, 2), (10, 4), (50, 0), (50, 10), (50, 20)] {
        let (a, b, sent) =
            jitter_pair(Duration::from_millis(delay), Duration::from_millis(jitter)).await?;
        let line = match bulk_tcp(&b, &a, BULK, REPORT_LIMIT).await {
            Ok(elapsed) => format!("{elapsed:.2?}"),
            Err(e) => format!("failed: {e}"),
        };
        println!(
            "delay {delay} ms + up to {jitter} ms: {} MiB in {line}, {} full-size segments sent",
            BULK >> 20,
            sent.load(Ordering::Relaxed),
        );
    }
    Ok(())
}
