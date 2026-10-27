#![allow(clippy::unwrap_used, reason = "benchmark harness")]

//! Bulk TCP send through two netstacks wired back to back in process (no engine, no
//! encryption, no loss): stack `a`'s source feeds stack `b`'s sink and the other way round,
//! so the time is the user-space TCP/IP stack's alone, both drivers and both smoltcp
//! sockets. One and four persistent connections at the default MTU and configuration; an
//! iteration sends `CHUNK_BYTES` split between the streams and ends when the receiver read
//! all of it. `netstack_send` runs on four runtime workers (the stacks and the application
//! tasks in parallel, as in a node), `netstack_send_1cpu` on one thread (the summed cost of
//! both ends, with less scheduling noise). Built against a smoltcp fork tag this compares the tags' sender; see
//! "Netstack throughput" in `docs/architecture.md`.
//!
//! `netstack_udp_send` and `netstack_udp_send_1cpu` send UDP the same way: one and four
//! connected sockets of stack `a`, flows without a context, each to a bound socket of `b`.
//! An iteration sends `DATAGRAMS` datagrams of `DATAGRAM` bytes in batches of `BATCH` and
//! ends when the receivers took all of them; a batch fits the receivers' queues, so none
//! is lost. `netstack_udp_flow_send` and `netstack_udp_flow_send_1cpu` send the same load
//! to flows `b` hands out on `incoming_udp` instead of bound sockets.
//!
//! Each case also runs with `b`'s input labeled (`_labeled`): the wire from `a` to `b` sets
//! the ingress label on every packet, so `b`'s connections and flows are labeled and every
//! segment and datagram into `b` is checked against its lifetime's label. Unlabeled and
//! labeled cases of one count run one after the other:
//!
//! ```text
//! cargo bench -p nsplane-netstack --bench send_stream
//! ```

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::time::Duration;

use criterion::{Criterion, Throughput};
use futures_core::Stream;
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_netstack::{
    DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Bytes per iteration, split evenly between the streams.
const CHUNK_BYTES: usize = 8 << 20;
/// Bytes per application write and read.
const IO: usize = 64 << 10;
/// TCP port of the receiving stack.
const PORT: u16 = 9000;
/// Datagrams per UDP iteration.
const DATAGRAMS: usize = 1024;
/// Datagrams in flight at once, split between the flows: fewer than a bound socket queues
/// (256 by default).
const BATCH: usize = 128;
/// UDP payload bytes.
const DATAGRAM: usize = 1200;
/// First UDP port of the receiving stack, one per flow.
const UDP_PORT: u16 = 5000;

/// The ingress label of `b`'s input in the labeled cases.
const LABEL: NonZeroU64 = NonZeroU64::MIN;

/// Forwards every packet from `from` to `to`, with the ingress label `label` if given.
async fn wire(mut from: NetStackSource, to: NetStackSink, label: Option<NonZeroU64>) {
    while let Ok(mut packet) = from.recv().await {
        if label.is_some() {
            packet.set_tag(label);
        }
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// Two stacks, `10.0.0.1` and `10.0.0.2`, wired back to back; `b`'s input carries `label`.
fn pair(label: Option<NonZeroU64>) -> (NetStackHandle, NetStackHandle) {
    let config =
        |last: u8| NetStackConfig::new(vec![(IpAddr::from([10, 0, 0, last]), 24)], DEFAULT_MTU);
    let (a_stack, a) = NetStack::new(config(1));
    let (b_stack, b) = NetStack::new(config(2));
    let (a_source, a_sink) = a_stack.split();
    let (b_source, b_sink) = b_stack.split();
    tokio::spawn(wire(a_source, b_sink, label));
    tokio::spawn(wire(b_source, a_sink, None));
    (a, b)
}

/// The cases of one count: unlabeled, then labeled.
fn cases(name: &str, count: usize) -> [(String, Option<NonZeroU64>); 2] {
    [
        (format!("{name}_{count}"), None),
        (format!("{name}_{count}_labeled"), Some(LABEL)),
    ]
}

/// `streams` connections from stack `10.0.0.1` to stack `10.0.0.2`: a sender per
/// connection that writes the byte counts it is given, and a receiver per connection that
/// reports every read's length on the returned channel.
async fn streams(
    streams: usize,
    label: Option<NonZeroU64>,
) -> (
    Vec<mpsc::UnboundedSender<usize>>,
    mpsc::UnboundedReceiver<usize>,
) {
    let (a, b) = pair(label);
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

/// `flows` UDP flows from stack `10.0.0.1` to stack `10.0.0.2`: a sender per flow that
/// sends the datagram counts it is given, and a receiver per flow that reports every
/// datagram on the returned channel.
async fn udp_flows(
    flows: usize,
    label: Option<NonZeroU64>,
) -> (
    Vec<mpsc::UnboundedSender<usize>>,
    mpsc::UnboundedReceiver<()>,
) {
    let (a, b) = pair(label);
    let (recv_tx, recv_rx) = mpsc::unbounded_channel();
    let mut senders = Vec::with_capacity(flows);
    for port in (UDP_PORT..).take(flows) {
        let target = SocketAddr::from(([10, 0, 0, 2], port));
        let mut server = b.bind_udp(target).await.unwrap();
        let received = recv_tx.clone();
        tokio::spawn(async move {
            while server.recv_from().await.is_ok() {
                if received.send(()).is_err() {
                    break;
                }
            }
        });
        let socket = a.connect_udp(target).await.unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel::<usize>();
        tokio::spawn(async move {
            let data = vec![0x5a; DATAGRAM];
            while let Some(count) = rx.recv().await {
                for _ in 0..count {
                    socket.send(&data).await.unwrap();
                }
            }
        });
        senders.push(tx);
    }
    (senders, recv_rx)
}

/// `flows` UDP flows from stack `10.0.0.1` to stack `10.0.0.2`, like [`udp_flows`], each
/// received as a flow from `b`'s `incoming_udp`, opened by one datagram before the run.
async fn incoming_flows(
    flows: usize,
    label: Option<NonZeroU64>,
) -> (
    Vec<mpsc::UnboundedSender<usize>>,
    mpsc::UnboundedReceiver<()>,
) {
    let (a, b) = pair(label);
    let mut incoming = b.incoming_udp();
    let (recv_tx, recv_rx) = mpsc::unbounded_channel();
    let mut senders = Vec::with_capacity(flows);
    for port in (UDP_PORT..).take(flows) {
        let target = SocketAddr::from(([10, 0, 0, 2], port));
        let socket = a.connect_udp(target).await.unwrap();
        socket.send(b"open").await.unwrap();
        let mut flow = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx))
            .await
            .unwrap();
        assert_eq!(flow.ingress_label(), label);
        flow.recv().await.unwrap();
        let received = recv_tx.clone();
        tokio::spawn(async move {
            while flow.recv().await.is_some() {
                if received.send(()).is_err() {
                    break;
                }
            }
        });
        let (tx, mut rx) = mpsc::unbounded_channel::<usize>();
        tokio::spawn(async move {
            let data = vec![0x5a; DATAGRAM];
            while let Some(count) = rx.recv().await {
                for _ in 0..count {
                    socket.send(&data).await.unwrap();
                }
            }
        });
        senders.push(tx);
    }
    (senders, recv_rx)
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
        for (case, count, label) in [1, 4]
            .into_iter()
            .flat_map(|count| cases("streams", count).map(|(case, label)| (case, count, label)))
        {
            let (senders, mut reads) = runtime.block_on(streams(count, label));
            group.bench_function(case, |bench| {
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

fn bench_udp_send(c: &mut Criterion) {
    udp_send(c, "netstack_udp_send", false);
}

fn bench_udp_flow_send(c: &mut Criterion) {
    udp_send(c, "netstack_udp_flow_send", true);
}

/// The UDP groups `name` and `name_1cpu`, to bound sockets or to `incoming` flows.
fn udp_send(c: &mut Criterion, name: &str, incoming: bool) {
    let runtimes = [
        (name.to_owned(), tokio::runtime::Builder::new_multi_thread()),
        (
            format!("{name}_1cpu"),
            tokio::runtime::Builder::new_current_thread(),
        ),
    ];
    for (name, mut builder) in runtimes {
        let runtime = builder.worker_threads(4).enable_time().build().unwrap();
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Elements(DATAGRAMS as u64));
        group.sample_size(20);
        group.measurement_time(Duration::from_secs(10));
        for (case, count, label) in [1, 4]
            .into_iter()
            .flat_map(|count| cases("flows", count).map(|(case, label)| (case, count, label)))
        {
            let (senders, mut received) = if incoming {
                runtime.block_on(incoming_flows(count, label))
            } else {
                runtime.block_on(udp_flows(count, label))
            };
            group.bench_function(case, |bench| {
                bench.iter_custom(|iters| {
                    runtime.block_on(async {
                        let batches = DATAGRAMS / BATCH * usize::try_from(iters).unwrap();
                        let started = Instant::now();
                        for _ in 0..batches {
                            for sender in &senders {
                                sender.send(BATCH / count).unwrap();
                            }
                            for _ in 0..BATCH {
                                received.recv().await.unwrap();
                            }
                        }
                        started.elapsed()
                    })
                });
            });
        }
        group.finish();
    }
}

criterion::criterion_group!(benches, bench_send, bench_udp_send, bench_udp_flow_send);
criterion::criterion_main!(benches);
