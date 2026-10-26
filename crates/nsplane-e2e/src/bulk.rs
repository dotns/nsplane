//! Shared bulk TCP transfer between two stack nodes, for the netstack throughput tests.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};

use crate::{Family, StackNode, TRANSFER, TestResult, next_within};

/// The port of the bulk transfers' server.
const TCP_PORT: u16 = 9000;

/// `len` bytes whose pattern (period 251) does not line up with any segment size, so
/// reordered or duplicated segments change the data.
pub fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// Megabytes (10^6 bytes) per second.
pub fn mb_per_s(bytes: usize, elapsed: Duration) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / elapsed.as_secs_f64() / 1e6
}

/// Sends `len` bytes from `client` to a connection `server` accepts, half-closes and checks
/// that the server read exactly those bytes within `limit`.
///
/// Returns the time from the established connection to the last byte read.
pub async fn bulk_tcp(
    client: &StackNode,
    server: &StackNode,
    len: usize,
    limit: Duration,
) -> TestResult<Duration> {
    let mut incoming = server.stack.incoming_tcp();
    let receiver = tokio::spawn(async move {
        let mut conn = next_within(&mut incoming, TRANSFER).await?;
        let mut received = Vec::with_capacity(len);
        conn.read_to_end(&mut received).await?;
        TestResult::Ok(received)
    });
    let target = server.socket_addr(Family::V4, TCP_PORT);
    let mut conn = timeout(TRANSFER, client.stack.connect_tcp(target)).await??;
    let started = Instant::now();
    let deadline = started + limit;
    let sent = data(len);
    let write = async {
        conn.write_all(&sent).await?;
        conn.shutdown().await
    };
    timeout_at(deadline, write).await??;
    let received = timeout_at(deadline, receiver).await???;
    let elapsed = started.elapsed();
    if received.len() != len {
        return Err(format!("{} of {len} bytes received", received.len()).into());
    }
    if received != sent {
        return Err("the transfer changed the data".into());
    }
    Ok(elapsed)
}
