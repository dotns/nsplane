//! Parallel bulk TCP streams between two netstacks over two engines on the in-process
//! channel link, at the default MTU, without and with `NetStackConfig::tcp_send_budget`.
//! The asserted test checks that four streams arrive intact, in order and with their EOF;
//! the ignored `streams_throughput` compares the aggregate of one and four streams and the
//! receiving engine's sink-full drops, and checks that without a send budget four streams
//! reach at least `MIN_FOUR_STREAM_SHARE` of one. Run it in release:
//!
//! ```text
//! cargo test --release -p nsplane-e2e --test netstack_multistream -- --ignored --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, DROP_SINK_FULL, EngineBuilder};
use nsplane_e2e::{Family, MTU, StackNode, TRANSFER, TestResult, next_within};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_packet::{Ecn, Path, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

/// TCP port of the receiving stack.
const PORT: u16 = 9000;
/// Bytes per write and per read buffer of the application.
const CHUNK: usize = 64 << 10;
/// Bytes per stream of the asserted transfer.
const CHECKED: usize = 4 << 20;
/// Bytes per measured run, split evenly between its streams.
const MEASURED: usize = 1 << 30;
/// Upper bound for a measured run.
const MEASURED_LIMIT: Duration = Duration::from_secs(120);
/// A send budget of one default send buffer: 512 IPv4-sized segments.
const BUDGET: usize = (MTU as usize - 40) * 512;
/// Smallest share of the one-stream aggregate four streams must reach without a send
/// budget. Measured four- to one-stream ratios were 1.00-1.11 (one stream 730-785 MB/s);
/// before the smoltcp fork's sender fixes four streams reached 0.2-0.3 of one.
const MIN_FOUR_STREAM_SHARE: f64 = 0.8;

/// Byte `i` of stream `stream`: a pattern (period 251) that does not line up with any
/// segment or chunk size and differs between streams, so reordered, duplicated or
/// crossed bytes change the data.
const fn pattern(stream: usize, i: usize) -> u8 {
    ((i + stream * 61) % 251).to_le_bytes()[0]
}

/// A stack node with key seed `seed` on `transport` at `at`, its stack's send budget set
/// to `budget`.
fn stack_node(
    seed: u8,
    at: (TransportId, SocketAddr),
    transport: ChannelTransport,
    budget: Option<usize>,
) -> TestResult<StackNode> {
    let ip4 = Ipv4Addr::new(10, 0, 0, seed);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
    let (stack, handle) = NetStack::new(NetStackConfig {
        tcp_send_budget: budget,
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

/// Two stack nodes (seeds 1 and 2) with send budget `budget`, linked by a loss-free
/// channel transport pair and introduced to each other.
async fn pair(budget: Option<usize>) -> TestResult<(StackNode, StackNode)> {
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
    let a = stack_node(1, ends.0, link_a, budget)?;
    let b = stack_node(2, ends.1, link_b, budget)?;
    a.handle
        .add_or_update_peer(b.as_peer(a.path.transport))
        .await?;
    b.handle
        .add_or_update_peer(a.as_peer(b.path.transport))
        .await?;
    Ok((a, b))
}

/// Streams `len` pattern bytes on each of `streams` connections from `a` to `b` at once
/// and checks every byte when `check` is set. The first byte of a stream is its index.
/// Returns the time from the first connect to the last EOF.
async fn streams(
    a: &StackNode,
    b: &StackNode,
    streams: usize,
    len: usize,
    check: bool,
    limit: Duration,
) -> TestResult<Duration> {
    let target = b.socket_addr(Family::V4, PORT);
    let mut incoming = b.stack.incoming_tcp();
    let receivers = tokio::spawn(async move {
        let mut readers = JoinSet::new();
        for _ in 0..streams {
            let mut conn = next_within(&mut incoming, TRANSFER).await?;
            readers.spawn(async move {
                let stream = usize::from(conn.read_u8().await?);
                let mut buf = vec![0; CHUNK];
                let mut received = 0;
                loop {
                    let n = conn.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    if check
                        && let Some(i) = (0..n).find(|&i| buf[i] != pattern(stream, received + i))
                    {
                        return Err(
                            format!("stream {stream}: byte {} changed", received + i).into()
                        );
                    }
                    received += n;
                }
                TestResult::Ok(received)
            });
        }
        let mut lengths = Vec::new();
        while let Some(received) = readers.join_next().await {
            lengths.push(received??);
        }
        TestResult::Ok(lengths)
    });

    let started = Instant::now();
    let mut writers = JoinSet::new();
    for stream in 0..streams {
        let mut conn = timeout(TRANSFER, a.stack.connect_tcp(target)).await??;
        writers.spawn(async move {
            let index = u8::try_from(stream)?;
            conn.write_u8(index).await?;
            // `CHUNK * 2` bytes of pattern hold every `CHUNK` window at any offset mod 251.
            let chunk: Vec<u8> = (0..CHUNK * 2).map(|i| pattern(stream, i)).collect();
            let mut sent = 0;
            while sent < len {
                let at = sent % 251;
                let n = CHUNK.min(len - sent);
                conn.write_all(&chunk[at..at + n]).await?;
                sent += n;
            }
            conn.shutdown().await?;
            TestResult::Ok(())
        });
    }
    timeout(limit, async {
        while let Some(written) = writers.join_next().await {
            written??;
        }
        TestResult::Ok(())
    })
    .await??;
    let lengths = timeout(limit, receivers).await???;
    let elapsed = started.elapsed();
    if lengths.len() != streams || lengths.iter().any(|&received| received != len) {
        return Err(format!("received {lengths:?}, {len} bytes per stream expected").into());
    }
    Ok(elapsed)
}

/// Megabytes (10^6 bytes) per second.
fn mb_per_s(bytes: usize, elapsed: Duration) -> f64 {
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / elapsed.as_secs_f64() / 1e6
}

/// Four parallel 4 MiB streams arrive intact over two engines, without and with a send
/// budget.
#[tokio::test(flavor = "multi_thread")]
async fn four_streams_intact() -> TestResult {
    for budget in [None, Some(BUDGET)] {
        let (a, b) = pair(budget).await?;
        streams(&a, &b, 4, CHECKED, true, TRANSFER).await?;
    }
    Ok(())
}

/// One and four streams over two engines, 1 GiB in total each, with the receiving
/// engine's sink-full drops, without and with a send budget of one default send buffer:
/// the four-stream anomaly of the netstack pair in process. Without a budget, four streams
/// must reach at least `MIN_FOUR_STREAM_SHARE` of the one-stream aggregate.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run in release with --nocapture"]
async fn streams_throughput() -> TestResult {
    for budget in [None, Some(BUDGET), None, Some(BUDGET)] {
        let mut rates = Vec::new();
        for count in [1, 4] {
            let (a, b) = pair(budget).await?;
            let elapsed = streams(&a, &b, count, MEASURED / count, false, MEASURED_LIMIT).await?;
            let dropped = b
                .handle
                .drop_counters()
                .await?
                .get(DROP_SINK_FULL)
                .copied()
                .unwrap_or(0);
            println!(
                "budget {budget:?}, {count} stream(s): {} MiB in {elapsed:.2?} = {:.1} MB/s, \
                 sink full {dropped}",
                MEASURED >> 20,
                mb_per_s(MEASURED, elapsed)
            );
            rates.push(mb_per_s(MEASURED, elapsed));
        }
        if let [one, four] = rates[..]
            && budget.is_none()
            && four < one * MIN_FOUR_STREAM_SHARE
        {
            return Err(format!(
                "four streams {four:.1} MB/s below {MIN_FOUR_STREAM_SHARE} x one stream {one:.1} MB/s"
            )
            .into());
        }
    }
    Ok(())
}
