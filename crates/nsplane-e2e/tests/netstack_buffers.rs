//! Bulk TCP in both directions between two netstacks over engines, with the TCP socket
//! buffers set through `NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer`: small (16 KiB),
//! large (4 MiB) and asymmetric (a small receive buffer against a large one) all complete
//! intact in bounded time.
//!
//! The ignored `throughput` test measures one direction for the default, 1 MiB and 4 MiB
//! buffers, with the engines' drop counters (a 4 MiB window overflows the 1024-packet
//! engine queue); run it in release:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test netstack_buffers -- --ignored --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder};
use nsplane_e2e::{Family, MTU, StackNode, TRANSFER, TestResult, next_within};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_packet::{Ecn, Path, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};

/// Bytes sent per asserted bulk transfer and direction.
const BULK: usize = 8 << 20;
/// Upper bound for one asserted bulk transfer, even in a debug build.
const BOUND: Duration = Duration::from_secs(20);
/// Bytes sent per measured bulk transfer.
const THROUGHPUT_BULK: usize = 64 << 20;
/// A small socket buffer: about a dozen segments.
const SMALL: usize = 16 << 10;
/// A large socket buffer.
const LARGE: usize = 4 << 20;
/// TCP port of the receiving stack.
const TCP_PORT: u16 = 9000;

/// `len` bytes whose pattern (period 251) does not line up with any segment size.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// Megabytes (10^6 bytes) per second.
fn mb_per_s(bytes: usize, elapsed: Duration) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / elapsed.as_secs_f64() / 1e6
}

/// Receive and send buffer sizes of one stack; `None` keeps the default.
#[derive(Debug, Clone, Copy)]
struct Buffers {
    rx: Option<usize>,
    tx: Option<usize>,
}

impl Buffers {
    const DEFAULT: Self = Self { rx: None, tx: None };

    const fn both(size: usize) -> Self {
        Self {
            rx: Some(size),
            tx: Some(size),
        }
    }
}

/// A stack node with key seed `seed` on `transport` at `at`, its stack's TCP buffers set
/// to `buffers`.
fn stack_node(
    seed: u8,
    at: (TransportId, SocketAddr),
    transport: ChannelTransport,
    buffers: Buffers,
) -> TestResult<StackNode> {
    let ip4 = Ipv4Addr::new(10, 0, 0, seed);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
    let (stack, handle) = NetStack::new(NetStackConfig {
        tcp_rx_buffer: buffers.rx,
        tcp_tx_buffer: buffers.tx,
        ..NetStackConfig::new(vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)], MTU)
    });
    let (source, sink) = stack.split();
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([seed; 32]))
        .transport(transport)
        .build()?;
    Ok(StackNode {
        handle: engine.handle(),
        engine,
        stack: handle,
        secret: StaticSecret::from([seed; 32]),
        ip4,
        ip6,
        path: Path {
            transport: at.0,
            addr: at.1,
            ecn: Ecn::NotEct,
        },
    })
}

/// Two stack nodes (seeds 1 and 2) with TCP buffers `a` and `b`, linked by a channel
/// transport pair and introduced to each other.
async fn pair(a: Buffers, b: Buffers) -> TestResult<(StackNode, StackNode)> {
    let ends = (
        (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], 1000)),
        ),
        (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], 2000)),
        ),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, ends.0, ends.1);
    let a = stack_node(1, ends.0, link_a, a)?;
    let b = stack_node(2, ends.1, link_b, b)?;
    a.handle
        .add_or_update_peer(b.as_peer(a.path.transport))
        .await?;
    b.handle
        .add_or_update_peer(a.as_peer(b.path.transport))
        .await?;
    Ok((a, b))
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

/// [`BULK`] bytes from `b` to `a`, then from `a` to `b`, each within [`BOUND`].
async fn both_directions(a: Buffers, b: Buffers) -> TestResult {
    let (a, b) = pair(a, b).await?;
    bulk_tcp(&b, &a, BULK, BOUND).await?;
    bulk_tcp(&a, &b, BULK, BOUND).await?;
    Ok(())
}

/// 16 KiB buffers on both stacks: a window of about a dozen segments.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_tcp_with_small_buffers() -> TestResult {
    both_directions(Buffers::both(SMALL), Buffers::both(SMALL)).await
}

/// 4 MiB buffers on both stacks: a scaled window well beyond the default.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_tcp_with_large_buffers() -> TestResult {
    both_directions(Buffers::both(LARGE), Buffers::both(LARGE)).await
}

/// A small receive buffer on one stack against large buffers on the other, and a large
/// receive buffer behind a small send buffer: each direction runs at the smaller window.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_tcp_with_asymmetric_buffers() -> TestResult {
    let small_rx = Buffers {
        rx: Some(SMALL),
        tx: Some(LARGE),
    };
    both_directions(small_rx, Buffers::both(LARGE)).await
}

/// The non-zero engine drop counters and the stacks' `egress_full` of `nodes`.
async fn drops(nodes: &[&StackNode]) -> TestResult<String> {
    let mut report = Vec::new();
    for node in nodes {
        let counters = node.handle.drop_counters().await?;
        let engine: Vec<String> = counters
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect();
        report.push(format!(
            "{}: [{}] egress_full={}",
            node.ip4,
            engine.join(" "),
            node.stack.stats().egress_full
        ));
    }
    Ok(report.join("; "))
}

/// Netstack TCP throughput for the default, 1 MiB and 4 MiB socket buffers on both stacks.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn throughput() -> TestResult {
    for (name, buffers) in [
        ("default", Buffers::DEFAULT),
        ("1 MiB", Buffers::both(1 << 20)),
        ("4 MiB", Buffers::both(LARGE)),
    ] {
        let (a, b) = pair(buffers, buffers).await?;
        let elapsed = bulk_tcp(&b, &a, THROUGHPUT_BULK, TRANSFER * 2).await?;
        println!(
            "tcp, {name} buffers: {} MiB in {elapsed:.2?} = {:.1} MB/s, drops {}",
            THROUGHPUT_BULK >> 20,
            mb_per_s(THROUGHPUT_BULK, elapsed),
            drops(&[&a, &b]).await?
        );
    }
    Ok(())
}
