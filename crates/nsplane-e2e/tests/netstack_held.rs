//! Bulk TCP through two netstacks over a link that delivers in slots, as a Wi-Fi access
//! point does for a client in power save: everything sent within a slot arrives at its end,
//! at once. The first messages of a connection pass at once (the client is awake while it
//! connects), so the sender's first round-trip measurements are far below the later delay.
//! With the slot on the return direction only, the data arrives at once and the
//! acknowledgements late and in clumps.
//!
//! The asserted tests are ignored until the sender stops taking late acknowledgements for
//! losses (a known issue in `CHANGELOG.md`). The ignored `report` test prints the transfer
//! times and segment counts per slot; run it in release:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test netstack_held -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use nsplane_e2e::bulk::bulk_tcp;
use nsplane_e2e::{HeldTransport, StackNode, TestResult, stack_pair_over};
use nsplane_netstack::DEFAULT_MTU;

/// Bytes sent per transfer.
const BULK: usize = 4 << 20;
/// Full-size segments [`BULK`] bytes need at the default MTU, rounded up: a segment
/// carries at least 1300 bytes, so about 190 of them are room for retransmissions.
const SEGMENTS: u64 = (BULK as u64).div_ceil(1300);
/// Data messages each held end sends before its link starts to hold: the handshake and
/// the first acknowledgements.
const AWAKE: u64 = 4;
/// The slot of the asserted tests.
const SLOT: Duration = Duration::from_millis(100);
/// Upper bound for an asserted transfer: about 3 s when no acknowledgement that is only
/// late is taken for a loss, minutes when every one is.
const BOUND: Duration = Duration::from_secs(20);
/// Upper bound for a transfer in the `report` test.
const REPORT_LIMIT: Duration = Duration::from_secs(120);

/// Which directions of the link are held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Both directions.
    Both,
    /// Only what the receiver of the bulk data sends: its acknowledgements.
    Return,
}

/// A receiving and a sending stack node over a link held as `held` in slots of `slot`, and
/// the count of full-size data messages the sender put on the link.
async fn held_pair(
    slot: Duration,
    held: Held,
) -> TestResult<(StackNode, StackNode, Arc<AtomicU64>)> {
    let sent = Arc::new(AtomicU64::new(0));
    let ignored = Arc::new(AtomicU64::new(0));
    // `stack_pair_over` wraps the first node's end first: the receiver's.
    let first = AtomicBool::new(true);
    let (receiver, sender) = stack_pair_over(
        DEFAULT_MTU,
        |link| {
            if first.swap(false, Ordering::Relaxed) {
                HeldTransport::new(link, Some(slot), AWAKE, Arc::clone(&ignored))
            } else {
                let slot = (held == Held::Both).then_some(slot);
                HeldTransport::new(link, slot, AWAKE, Arc::clone(&sent))
            }
        },
        |builder| builder,
    )
    .await?;
    Ok((receiver, sender, sent))
}

/// [`BULK`] bytes over a link held as `held` complete within [`BOUND`] with at most
/// [`SEGMENTS`] full-size segments sent.
async fn completes(held: Held) -> TestResult {
    let (receiver, sender, sent) = held_pair(SLOT, held).await?;
    bulk_tcp(&sender, &receiver, BULK, BOUND).await?;
    let sent = sent.load(Ordering::Relaxed);
    assert!(
        sent <= SEGMENTS,
        "{sent} full-size segments sent, {SEGMENTS} allowed"
    );
    Ok(())
}

/// Both directions held: every round trip takes one to two slots.
#[tokio::test]
#[ignore = "known issue: late acknowledgements are taken for losses"]
async fn bulk_tcp_over_a_held_link() -> TestResult {
    completes(Held::Both).await
}

/// Only the acknowledgements held, after round trips of well under a millisecond: the
/// sender must not take each late acknowledgement for a lost segment.
#[tokio::test]
#[ignore = "known issue: late acknowledgements are taken for losses"]
async fn bulk_tcp_with_held_acknowledgements() -> TestResult {
    completes(Held::Return).await
}

/// Transfer time and full-size segments sent per slot and held direction.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn report() -> TestResult {
    for held in [Held::Both, Held::Return] {
        for slot in [10, 100, 300, 1000] {
            let (receiver, sender, sent) = held_pair(Duration::from_millis(slot), held).await?;
            let line = match bulk_tcp(&sender, &receiver, BULK, REPORT_LIMIT).await {
                Ok(elapsed) => format!("{elapsed:.2?}"),
                Err(e) => format!("failed: {e}"),
            };
            println!(
                "{held:?}, slot {slot} ms: {} MiB in {line}, {} full-size segments sent ({SEGMENTS} allowed)",
                BULK >> 20,
                sent.load(Ordering::Relaxed),
            );
        }
    }
    Ok(())
}
