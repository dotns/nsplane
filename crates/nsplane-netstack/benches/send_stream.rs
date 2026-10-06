#![allow(clippy::unwrap_used, reason = "benchmark harness")]

//! Bulk TCP send through two netstacks wired back to back in process (no engine, no
//! encryption, no loss): stack `a`'s source feeds stack `b`'s sink and the other way round,
//! so the time is the user-space TCP/IP stack's alone, both drivers and both smoltcp
//! sockets. One and four persistent connections at the default MTU and configuration; an
//! iteration sends `CHUNK_BYTES` split between the streams and ends when the receiver read
//! all of it. `netstack_send` runs on four runtime workers (the stacks and the application
//! tasks in parallel, as in a node), `netstack_send_1cpu` on one thread (the summed cost of
//! both ends, with less scheduling noise). Built against a smoltcp fork tag this compares the tags' sender; see
//! "Netstack throughput" in `docs/architecture.md`:
//!
//! ```text
//! cargo bench -p nsplane-netstack --bench send_stream
//! ```

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use criterion::{Criterion, Throughput};
use futures_core::Stream;
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackSink, NetStackSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Bytes per iteration, split evenly between the streams.
const CHUNK_BYTES: usize = 8 << 20;
/// Bytes per application write and read.
const IO: usize = 64 << 10;
/// TCP port of the receiving stack.
const PORT: u16 = 9000;

/// Forwards every packet from `from` to `to`.
async fn wire(mut from: NetStackSource, to: NetStackSink) {
    while let Ok(packet) = from.recv().await {
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// `streams` connections from stack `10.0.0.1` to stack `10.0.0.2`: a sender per
/// connection that writes the byte counts it is given, and a receiver per connection that
/// reports every read's length on the returned channel.
async fn streams(
    streams: usize,
) -> (
    Vec<mpsc::UnboundedSender<usize>>,
    mpsc::UnboundedReceiver<usize>,
) {
    let config =
        |last: u8| NetStackConfig::new(vec![(IpAddr::from([10, 0, 0, last]), 24)], DEFAULT_MTU);
    let (a_stack, a) = NetStack::new(config(1));
    let (b_stack, b) = NetStack::new(config(2));
    let (a_source, a_sink) = a_stack.split();
    let (b_source, b_sink) = b_stack.split();
    tokio::spawn(wire(a_source, b_sink));
    tokio::spawn(wire(b_source, a_sink));

    let mut incoming = b.incoming_tcp();
    let (read_tx, read_rx) = mpsc::unbounded_channel();
    let mut senders = Vec::with_capacity(streams);
    let target = SocketAddr::from(([10, 0, 0, 2], PORT));
    for _ in 0..streams {
        let mut conn = a.connect_tcp(target).await.unwrap();
        let mut server = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx))
            .await
            .unwrap();
        let reads = read_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; IO];
            loop {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 || reads.send(n).is_err() {
                    break;
                }
            }
        });
        let (tx, mut rx) = mpsc::unbounded_channel::<usize>();
        tokio::spawn(async move {
            let data = vec![0x5a; IO];
            while let Some(mut len) = rx.recv().await {
                while len > 0 {
                    let n = len.min(IO);
                    conn.write_all(&data[..n]).await.unwrap();
                    len -= n;
                }
            }
        });
        senders.push(tx);
    }
    (senders, read_rx)
}

fn bench_send(c: &mut Criterion) {
    let runtimes = [
        ("netstack_send", tokio::runtime::Builder::new_multi_thread()),
        (
            "netstack_send_1cpu",
            tokio::runtime::Builder::new_current_thread(),
        ),
    ];
    for (name, mut builder) in runtimes {
        let runtime = builder.worker_threads(4).enable_time().build().unwrap();
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Bytes(CHUNK_BYTES as u64));
        group.sample_size(20);
        group.measurement_time(Duration::from_secs(10));
        for count in [1, 4] {
            let (senders, mut reads) = runtime.block_on(streams(count));
            group.bench_function(format!("streams_{count}"), |bench| {
                bench.iter_custom(|iters| {
                    runtime.block_on(async {
                        let per_stream = CHUNK_BYTES / count * usize::try_from(iters).unwrap();
                        let started = Instant::now();
                        for sender in &senders {
                            sender.send(per_stream).unwrap();
                        }
                        let mut received = 0;
                        while received < per_stream * count {
                            received += reads.recv().await.unwrap();
                        }
                        started.elapsed()
                    })
                });
            });
        }
        group.finish();
    }
}

criterion::criterion_group!(benches, bench_send);
criterion::criterion_main!(benches);
