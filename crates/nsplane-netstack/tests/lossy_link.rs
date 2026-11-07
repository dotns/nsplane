//! Many concurrent connections between two stacks over a link that drops what exceeds a
//! budget, as a relay does.
//!
//! The link repeats from its seed; initial sequence numbers and the stacks' task order do
//! not, so which connections are at risk differs between runs. A seed that passes by luck
//! is rare enough that all of them passing is not luck.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_core::Stream;
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_netstack::{
    Admission, NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource,
    TransparentConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

const MTU: u16 = 1280;
const HANDSHAKES: usize = 256;
const PORT: u16 = 7000;
const SIZE: usize = 4096;
/// Longer than the retransmissions any case needs: the clock is paused, so a timeout costs
/// no real time, and the back-off reaches 31 s under this loss.
const LIMIT: Duration = Duration::from_secs(120);

fn stack(address: IpAddr, admission: Admission) -> (NetStack, NetStackHandle) {
    let mut transparent = TransparentConfig::default();
    transparent.prefixes = vec![(address, 128)];
    let mut config = NetStackConfig::new(vec![(address, 128)], MTU);
    config.transparent = Some(transparent);
    config.listener_pool = HANDSHAKES;
    config.accept_capacity = HANDSHAKES;
    config.accept_backpressure = true;
    config.admission = admission;
    NetStack::new(config)
}

/// One link condition and how much is sent over it.
#[derive(Clone, Copy, Debug)]
struct Case {
    client: IpAddr,
    target: IpAddr,
    admission: Admission,
    seed: u64,
    connections: u32,
    /// Packets one direction carries per `window`; the rest are dropped.
    budget: usize,
    window: Duration,
    /// The time between two connections.
    stagger: Duration,
    /// The largest one-way delay of a packet.
    jitter: Duration,
}

/// A generator with a fixed sequence, so that a run repeats.
struct Random(u64);

impl Random {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Carries packets from `source` to `sink` under the conditions of `case`.
fn link(mut source: NetStackSource, sink: NetStackSink, seed: u64, case: Case) -> JoinHandle<()> {
    let sink = Arc::new(sink);
    let mut random = Random(seed);
    tokio::spawn(async move {
        let mut opened = Instant::now();
        let mut carried = 0;
        while let Ok(packet) = source.recv().await {
            if opened.elapsed() >= case.window {
                opened = Instant::now();
                carried = 0;
            }
            if carried >= case.budget {
                continue;
            }
            carried += 1;
            let jitter = u64::try_from(case.jitter.as_micros()).unwrap_or(1).max(1);
            let delay = Duration::from_micros(random.next() % jitter);
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                sleep(delay).await;
                let _ = sink.send(packet, PeerId::new(0)).await;
            });
        }
    })
}

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Admits every connection and echoes `SIZE` bytes on it.
fn serve(stack: &NetStackHandle) -> [JoinHandle<()>; 2] {
    let mut pending = stack.incoming_pending();
    let mut accepted = stack.incoming_tcp();
    let admit = tokio::spawn(async move {
        while let Some(flow) = next(&mut pending).await {
            flow.accept();
        }
    });
    let echo = tokio::spawn(async move {
        while let Some(mut connection) = next(&mut accepted).await {
            tokio::spawn(async move {
                let mut bytes = [0; SIZE];
                connection.read_exact(&mut bytes).await?;
                connection.write_all(&bytes).await?;
                connection.shutdown().await
            });
        }
    });
    [admit, echo]
}

async fn exchange(stack: NetStackHandle, target: SocketAddr) -> io::Result<()> {
    let mut connection = stack.connect_tcp(target).await?;
    connection.write_all(&[7; SIZE]).await?;
    let mut bytes = [0; SIZE];
    connection.read_exact(&mut bytes).await?;
    Ok(())
}

/// How many of the connections of `case` failed, with the target's failed handshakes.
async fn run(case: Case) -> (usize, u64) {
    let (client, client_handle) = stack(case.client, case.admission);
    let (server, server_handle) = stack(case.target, case.admission);
    let (client_source, client_sink) = client.split();
    let (server_source, server_sink) = server.split();
    let links = [
        link(client_source, server_sink, case.seed, case),
        link(server_source, client_sink, !case.seed, case),
    ];
    let served = serve(&server_handle);

    let target = SocketAddr::new(case.target, PORT);
    let exchanges: Vec<_> = (0..case.connections)
        .map(|index| {
            let stack = client_handle.clone();
            tokio::spawn(timeout(LIMIT, async move {
                sleep(case.stagger * index).await;
                exchange(stack, target).await
            }))
        })
        .collect();
    let mut failed = 0;
    for exchange in exchanges {
        if !matches!(exchange.await, Ok(Ok(Ok(())))) {
            failed += 1;
        }
    }
    let handshakes = server_handle.stats().handshake_failed;
    for task in links.iter().chain(&served) {
        task.abort();
    }
    (failed, handshakes)
}

/// A SYN-ACK lost to the budget makes the client send its SYN again; that SYN must not open
/// a second socket for the tuple, whose RST would end the connection.
#[tokio::test(start_paused = true)]
async fn concurrent_connections_survive_a_lossy_link() {
    let burst = Case {
        client: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into(),
        target: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).into(),
        admission: Admission::Decide {
            timeout: Duration::from_secs(5),
            max_pending: 1024,
        },
        seed: 0,
        connections: 50,
        budget: 8,
        window: Duration::from_millis(5),
        stagger: Duration::from_micros(500),
        jitter: Duration::from_millis(5),
    };
    let ipv4 = Case {
        client: Ipv4Addr::new(10, 0, 0, 1).into(),
        target: Ipv4Addr::new(10, 0, 0, 2).into(),
        ..burst
    };
    let mut failures = Vec::new();
    for row in [burst, ipv4] {
        for admission in [row.admission, Admission::Immediate] {
            for seed in 1..=16 {
                let case = Case {
                    admission,
                    seed: seed * 0x9E37_79B9,
                    ..row
                };
                let (failed, handshakes) = run(case).await;
                if failed != 0 || handshakes != 0 {
                    failures.push((case.target, admission, case.seed, failed, handshakes));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "target, admission, seed, lost connections, failed handshakes: {failures:?}"
    );
}
