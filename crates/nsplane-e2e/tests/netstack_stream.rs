//! One bulk TCP stream between two netstacks, either over two engines on the in-process
//! channel link or with the stacks wired to each other directly (no engine, no crypto),
//! at the default MTU. The asserted tests check that a stream arrives intact, in order and
//! with its EOF on both pairings; the ignored `stream_throughput_*` tests are the
//! single-stream loads used to profile the stack. Run it in release:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test netstack_stream -- --ignored --nocapture
//! ```

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use nsplane::{PacketSink, PacketSource};
use nsplane_e2e::{Family, StackNode, TRANSFER, TestResult, next_within, stack_pair_over};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use nsplane_packet::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout};

/// TCP port of the receiving stack.
const PORT: u16 = 9000;
/// Bytes per write and per read buffer of the application.
const CHUNK: usize = 64 << 10;
/// Bytes sent per asserted transfer.
const CHECKED: usize = 8 << 20;
/// Bytes sent per measured transfer: long enough for a stable profile.
const MEASURED: usize = 1 << 30;
/// Upper bound for a measured transfer.
const MEASURED_LIMIT: Duration = Duration::from_secs(120);

/// Byte `i` of a stream: a pattern (period 251) that does not line up with any segment or
/// chunk size, so reordered or duplicated bytes change the data.
const fn pattern(i: usize) -> u8 {
    (i % 251).to_le_bytes()[0]
}

/// Two stacks whose egress feeds the other's ingress directly, and their handles.
fn direct_pair() -> ((NetStackHandle, SocketAddr), (NetStackHandle, SocketAddr)) {
    let a = Ipv4Addr::new(10, 0, 0, 1);
    let b = Ipv4Addr::new(10, 0, 0, 2);
    let (stack_a, handle_a) =
        NetStack::new(NetStackConfig::new(vec![(IpAddr::V4(a), 32)], DEFAULT_MTU));
    let (stack_b, handle_b) =
        NetStack::new(NetStackConfig::new(vec![(IpAddr::V4(b), 32)], DEFAULT_MTU));
    let (source_a, sink_a) = stack_a.split();
    let (source_b, sink_b) = stack_b.split();
    tokio::spawn(wire(source_a, sink_b));
    tokio::spawn(wire(source_b, sink_a));
    (
        (handle_a, SocketAddr::new(IpAddr::V4(a), PORT)),
        (handle_b, SocketAddr::new(IpAddr::V4(b), PORT)),
    )
}

/// Moves every packet `source` emits into `sink` until either side stops.
async fn wire(mut source: impl PacketSource, sink: impl PacketSink) -> io::Result<()> {
    loop {
        let packet = source.recv().await?;
        sink.send(packet, PeerId::new(0)).await?;
    }
}

/// Two stack nodes over two engines on a loss-free channel link.
async fn engine_pair() -> TestResult<(StackNode, StackNode)> {
    stack_pair_over(DEFAULT_MTU, |link| link, |builder| builder).await
}

/// Streams `len` pattern bytes from `client` to a connection `server` accepts at `target`
/// in [`CHUNK`]-sized writes, then half-closes. The server reads until EOF, checking the
/// pattern when `check` is set. Returns the time from the established connection to EOF.
async fn stream(
    client: &NetStackHandle,
    server: &NetStackHandle,
    target: SocketAddr,
    len: usize,
    check: bool,
    limit: Duration,
) -> TestResult<Duration> {
    let mut incoming = server.incoming_tcp();
    let receiver = tokio::spawn(async move {
        let mut conn = next_within(&mut incoming, TRANSFER).await?;
        let mut buf = vec![0; CHUNK];
        let mut received = 0;
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if check && let Some(i) = (0..n).find(|&i| buf[i] != pattern(received + i)) {
                return Err(format!("byte {} changed", received + i).into());
            }
            received += n;
        }
        TestResult::Ok(received)
    });
    let mut conn = timeout(TRANSFER, client.connect_tcp(target)).await??;
    let started = Instant::now();
    let chunk: Vec<u8> = (0..CHUNK * 2).map(pattern).collect();
    let write = async {
        let mut sent = 0;
        while sent < len {
            // `CHUNK * 2` bytes of pattern hold every `CHUNK` window at any offset mod 251.
            let at = sent % 251;
            let n = CHUNK.min(len - sent);
            conn.write_all(&chunk[at..at + n]).await?;
            sent += n;
        }
        conn.shutdown().await
    };
    timeout(limit, write).await??;
    let received = timeout(limit, receiver).await???;
    let elapsed = started.elapsed();
    if received != len {
        return Err(format!("{received} of {len} bytes received").into());
    }
    Ok(elapsed)
}

/// Megabytes (10^6 bytes) per second.
fn mb_per_s(bytes: usize, elapsed: Duration) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / elapsed.as_secs_f64() / 1e6
}

/// 8 MiB stream intact over two directly wired stacks.
#[tokio::test(flavor = "multi_thread")]
async fn stream_intact_direct() -> TestResult {
    let ((a, _), (b, target)) = direct_pair();
    stream(&a, &b, target, CHECKED, true, TRANSFER).await?;
    Ok(())
}

/// 8 MiB stream intact over two engines.
#[tokio::test(flavor = "multi_thread")]
async fn stream_intact_engines() -> TestResult {
    let (a, b) = engine_pair().await?;
    let target = b.socket_addr(Family::V4, PORT);
    stream(&a.stack, &b.stack, target, CHECKED, true, TRANSFER).await?;
    Ok(())
}

/// Single-stream throughput over two engines, 1 GiB: the load for profiling the stack.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn stream_throughput_engines() -> TestResult {
    let (a, b) = engine_pair().await?;
    let target = b.socket_addr(Family::V4, PORT);
    let elapsed = stream(&a.stack, &b.stack, target, MEASURED, false, MEASURED_LIMIT).await?;
    println!(
        "stream, engines: {} MiB in {elapsed:.2?} = {:.1} MB/s",
        MEASURED >> 20,
        mb_per_s(MEASURED, elapsed)
    );
    Ok(())
}

/// Single-stream throughput over two directly wired stacks, 1 GiB: the stack's own cost.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn stream_throughput_direct() -> TestResult {
    let ((a, _), (b, target)) = direct_pair();
    let elapsed = stream(&a, &b, target, MEASURED, false, MEASURED_LIMIT).await?;
    println!(
        "stream, direct: {} MiB in {elapsed:.2?} = {:.1} MB/s",
        MEASURED >> 20,
        mb_per_s(MEASURED, elapsed)
    );
    Ok(())
}
