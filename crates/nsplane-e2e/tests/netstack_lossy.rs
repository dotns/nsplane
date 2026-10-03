//! Bulk TCP through two netstacks over engines whose transport loses data messages: the
//! transfer completes intact and in bounded time, with a loss-free reference run. Eight
//! parallel echoes through small engine queues, which drop packets at the stack's full
//! sink, complete without and with loss on the link.
//!
//! The ignored `throughput` test measures netstack TCP and UDP throughput over the same
//! in-process engine pair, with and without loss; run it in release:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nsplane_e2e::{
    Bottleneck, Family, LossyTransport, StackNode, TRANSFER, TestResult, next_within,
    serve_tcp_echo, stack_pair_over,
};
use nsplane_netstack::DEFAULT_MTU;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};

/// Bytes sent per asserted bulk transfer.
const BULK: usize = 8 << 20;
/// Data messages dropped per 1000 on each end of the lossy link.
const LOSS_PERMILLE: u64 = 10;
/// Upper bound for a bulk transfer over the lossy link, well under [`TRANSFER`] even in a
/// debug build.
const LOSSY_BOUND: Duration = Duration::from_secs(15);
/// Bytes sent per measured loss-free bulk transfer.
const THROUGHPUT_BULK: usize = 64 << 20;
/// Bytes sent per measured bulk transfer over a lossy link.
const LOSSY_THROUGHPUT_BULK: usize = 16 << 20;
/// Upper bound for a measured bulk transfer; a slower one is reported as stalled.
const THROUGHPUT_LIMIT: Duration = Duration::from_secs(60);
/// Rate of the measured bottleneck link, in bytes per second.
const BOTTLENECK_RATE: u64 = 25_000_000;
/// Datagrams the measured bottleneck buffers, fewer than a full TCP window.
const BOTTLENECK_BUFFER: usize = 64;
/// Parallel echo connections per run of the parallel tests.
const FLOWS: usize = 8;
/// Bytes each parallel connection sends and gets echoed.
const FLOW_BULK: usize = 1 << 20;
/// Engine queue capacity of the parallel tests: small enough that the engine drops
/// decrypted packets at the stack's full sink (`DROP_SINK_FULL`) under eight flows.
const SMALL_QUEUES: usize = 256;
/// Data messages dropped per 1000 on each end of the lossy link of the parallel test.
const PARALLEL_LOSS_PERMILLE: u64 = 20;
/// Upper bound for every parallel connection to finish its echo, even in a debug build.
const PARALLEL_BOUND: Duration = Duration::from_secs(60);
/// TCP port of the echo server of the parallel tests.
const ECHO_PORT: u16 = 7;
/// TCP port of the receiving stack.
const TCP_PORT: u16 = 9000;
/// UDP port of the receiving stack.
const UDP_PORT: u16 = 9001;
/// Datagrams sent per UDP measurement.
const DATAGRAMS: usize = 50_000;
/// Payload bytes per datagram, leaving room for the IP and UDP headers at the default MTU.
const DATAGRAM: usize = 1200;
/// How long the UDP receiver waits for a further datagram before it stops counting.
const UDP_GAP: Duration = Duration::from_millis(500);

/// `len` bytes whose pattern (period 251) does not line up with any segment size, so
/// reordered or duplicated segments change the data.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// Megabytes (10^6 bytes) per second.
fn mb_per_s(bytes: usize, elapsed: Duration) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / elapsed.as_secs_f64() / 1e6
}

/// Two stack nodes whose link drops `permille` of the data messages in each direction, and
/// the count of messages dropped so far.
async fn lossy_pair(permille: u64) -> TestResult<(StackNode, StackNode, Arc<AtomicU64>)> {
    let dropped = Arc::new(AtomicU64::new(0));
    let (a, b) = stack_pair_over(
        DEFAULT_MTU,
        |link| LossyTransport::new(link, permille, Arc::clone(&dropped)),
        |builder| builder,
    )
    .await?;
    Ok((a, b, dropped))
}

/// Sends `len` bytes from `client` to a connection `server` accepts, half-closes and checks
/// that the server read exactly those bytes within `limit`. Returns the time from the
/// established connection to the last byte read.
async fn bulk_tcp(
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

/// [`bulk_tcp`] of `len` bytes within [`THROUGHPUT_LIMIT`] as a report line; a transfer
/// that runs out of time is reported, any other failure is returned.
async fn measure_tcp(client: &StackNode, server: &StackNode, len: usize) -> TestResult<String> {
    match bulk_tcp(client, server, len, THROUGHPUT_LIMIT).await {
        Ok(elapsed) => Ok(format!(
            "{} MiB in {elapsed:.2?} = {:.1} MB/s",
            len >> 20,
            mb_per_s(len, elapsed)
        )),
        Err(e) if e.is::<tokio::time::error::Elapsed>() => Ok(format!(
            "{} MiB stalled, not done after {THROUGHPUT_LIMIT:?}",
            len >> 20
        )),
        Err(e) => Err(e),
    }
}

/// Sends [`DATAGRAMS`] datagrams of [`DATAGRAM`] bytes from `client` to a flow `server`
/// accepts. Returns how many arrived and the time from the first send to the last arrival.
async fn udp_burst(client: &StackNode, server: &StackNode) -> TestResult<(usize, Duration)> {
    let mut incoming = server.stack.incoming_udp();
    let receiver = tokio::spawn(async move {
        let mut flow = next_within(&mut incoming, TRANSFER).await?;
        let mut received = 1;
        let mut last = Instant::now();
        while received < DATAGRAMS {
            match timeout(UDP_GAP, flow.recv()).await {
                Ok(Some(_)) => {
                    received += 1;
                    last = Instant::now();
                }
                Ok(None) | Err(_) => break,
            }
        }
        TestResult::Ok((received, last))
    });
    let socket = client
        .stack
        .bind_udp(client.socket_addr(Family::V4, 0))
        .await?;
    let target = server.socket_addr(Family::V4, UDP_PORT);
    let payload = data(DATAGRAM);
    let started = Instant::now();
    for _ in 0..DATAGRAMS {
        socket.send_to(&payload, target).await?;
    }
    let (received, last) = timeout(TRANSFER, receiver).await???;
    Ok((received, last.duration_since(started)))
}

/// Runs [`FLOWS`] connections from `client` to the echo server on `server` at once, each
/// sending [`FLOW_BULK`] bytes (its own pattern) while reading the echo, and checks every
/// echo within [`PARALLEL_BOUND`]. Returns the time until the last echo completed.
async fn parallel_echo(client: &StackNode, server: &StackNode) -> TestResult<Duration> {
    serve_tcp_echo(&server.stack);
    let target = server.socket_addr(Family::V4, ECHO_PORT);
    let started = Instant::now();
    let deadline = started + PARALLEL_BOUND;
    let flows: Vec<_> = (0..FLOWS)
        .map(|flow| {
            let stack = client.stack.clone();
            tokio::spawn(async move {
                let conn = stack.connect_tcp(target).await?;
                let sent: Vec<u8> = data(FLOW_BULK + flow).split_off(flow);
                let (mut reader, mut writer) = tokio::io::split(conn);
                let write = async {
                    writer.write_all(&sent).await?;
                    writer.shutdown().await
                };
                let read = async {
                    let mut echoed = Vec::with_capacity(FLOW_BULK);
                    reader.read_to_end(&mut echoed).await?;
                    Ok::<_, std::io::Error>(echoed)
                };
                let ((), echoed) = tokio::try_join!(write, read)?;
                if echoed != sent {
                    return Err(format!(
                        "flow {flow}: {} of {FLOW_BULK} bytes echoed, or changed",
                        echoed.len()
                    )
                    .into());
                }
                TestResult::Ok(())
            })
        })
        .collect();
    for (flow, task) in flows.into_iter().enumerate() {
        timeout_at(deadline, task)
            .await
            .map_err(|_| format!("flow {flow} stalled for {PARALLEL_BOUND:?}"))???;
    }
    Ok(started.elapsed())
}

/// Two stack nodes with [`SMALL_QUEUES`] engine queues whose link drops `permille` of the
/// data messages in each direction.
async fn small_queue_pair(permille: u64) -> TestResult<(StackNode, StackNode)> {
    let dropped = Arc::new(AtomicU64::new(0));
    stack_pair_over(
        DEFAULT_MTU,
        |link| LossyTransport::new(link, permille, Arc::clone(&dropped)),
        |builder| builder.queue_capacity(SMALL_QUEUES),
    )
    .await
}

/// Eight parallel echoes through small engine queues finish without loss on the link: the
/// packets the engine drops at the stack's full sink are recovered, and no connection
/// stalls in smoltcp's zero-window handling.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_echo_without_loss() -> TestResult {
    let (a, b) = small_queue_pair(0).await?;
    parallel_echo(&b, &a).await?;
    Ok(())
}

/// Eight parallel echoes through small engine queues finish over a link that drops 2 % of
/// the data messages in each direction.
#[tokio::test(flavor = "multi_thread")]
async fn parallel_echo_with_loss() -> TestResult {
    let (a, b) = small_queue_pair(PARALLEL_LOSS_PERMILLE).await?;
    parallel_echo(&b, &a).await?;
    Ok(())
}

/// The reference: 8 MiB over a loss-free link.
#[tokio::test]
async fn bulk_tcp_without_loss() -> TestResult {
    let (a, b, dropped) = lossy_pair(0).await?;
    bulk_tcp(&b, &a, BULK, TRANSFER).await?;
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    Ok(())
}

/// 8 MiB over a link that drops 1 % of the data messages in each direction completes intact
/// within [`LOSSY_BOUND`].
///
/// At 2-3 % loss smoltcp recovers mostly through retransmission timeouts (at least 1 s
/// each; it has no SACK and no retransmission on a partial ACK), so the same transfer takes
/// 15-40 s in a debug build.
#[tokio::test]
async fn bulk_tcp_with_loss() -> TestResult {
    let (a, b, dropped) = lossy_pair(LOSS_PERMILLE).await?;
    bulk_tcp(&b, &a, BULK, LOSSY_BOUND).await?;
    assert!(
        dropped.load(Ordering::Relaxed) > 0,
        "the link dropped nothing"
    );
    Ok(())
}

/// Netstack throughput: TCP without loss, at 1 % and 3 % loss and through a bottleneck
/// whose buffer is smaller than a TCP window, then a UDP burst.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn throughput() -> TestResult {
    for permille in [0, 10, 30] {
        let (a, b, dropped) = lossy_pair(permille).await?;
        let len = if permille == 0 {
            THROUGHPUT_BULK
        } else {
            LOSSY_THROUGHPUT_BULK
        };
        let report = measure_tcp(&b, &a, len).await?;
        println!(
            "tcp, loss {permille}/1000: {report} ({} dropped)",
            dropped.load(Ordering::Relaxed)
        );
    }

    let dropped = Arc::new(AtomicU64::new(0));
    let (a, b) = stack_pair_over(
        DEFAULT_MTU,
        |link| {
            Bottleneck::new(
                link,
                BOTTLENECK_RATE,
                BOTTLENECK_BUFFER,
                Arc::clone(&dropped),
            )
        },
        |builder| builder,
    )
    .await?;
    let report = measure_tcp(&b, &a, LOSSY_THROUGHPUT_BULK).await?;
    println!(
        "tcp, {} MB/s bottleneck, {BOTTLENECK_BUFFER} datagrams of buffer: {report} ({} dropped)",
        BOTTLENECK_RATE / 1_000_000,
        dropped.load(Ordering::Relaxed)
    );

    let (a, b, _) = lossy_pair(0).await?;
    let (received, elapsed) = udp_burst(&b, &a).await?;
    println!(
        "udp: {received} of {DATAGRAMS} datagrams of {DATAGRAM} B in {elapsed:.2?} = {:.1} MB/s",
        mb_per_s(received * DATAGRAM, elapsed),
    );
    Ok(())
}
