#![allow(clippy::unwrap_used, reason = "benchmark harness")]

//! Local-side graph primitives on a current-thread runtime, per packet, for 64 B and
//! 1420 B packets: `pipe` sends a batch of packets into a pipe and reads them back with
//! `recv_batch`, and `alloc_send_recv` also allocates each packet with `PipeSink::alloc`
//! and recycles it into the source once read; `pump` moves the packets from one pipe into another with `pump` while a
//! task drains the second pipe. `pipe_to_writer` has a long-running `pump` move packets a
//! producer allocates with `PipeSink::alloc` into a sink that consumes them like a device
//! write and drops the buffers; `pipe_to_writer_spent` has the sink hand them back through
//! `send_batch_spent`, so `pump` recycles them into the pipe's pool.
//!
//! The wrapper groups send through a wrapper into roomy pipes and read the packets back,
//! each with its baseline next to it: `splitter` compares a reading route closure
//! (`Splitter::new`) with a rewriting one (`Splitter::new_map`) over two sinks; `map_sink`
//! compares `MapSink::new` with `MapSink::with_after` (a counter as the hook) on `send`
//! and `send_batch`; `swap_sink` compares the bare pipe with `SwapSink` and with
//! `SwapSink<AbortSink>` before any abort.

use std::collections::VecDeque;
use std::hint::black_box;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{BatchSize, Criterion, Throughput};
use nsplane::{
    AbortSink, MapSink, MapVerdict, PacketBatch, PacketBuf, PacketSink, PacketSource, PeerId,
    PipeSource, Splitter, SwapSink, pipe, pump,
};
use tokio::sync::watch;

/// Packets per iteration.
const PACKETS: usize = 1024;

/// Packet sizes: a minimal packet and a full one at MTU 1420.
const SIZES: [usize; 2] = [64, 1420];

fn packets(size: usize) -> Vec<PacketBuf> {
    (0..PACKETS)
        .map(|_| PacketBuf::from_packet(&vec![0x45; size]))
        .collect()
}

/// The byte a splitter routes on: the last byte of the IPv4 destination.
const ROUTE_BYTE: usize = 19;

/// The byte a rewriting route closure changes: the IPv4 TTL.
const TTL_BYTE: usize = 8;

/// Packets alternating between splitter sink 0 and sink 1.
fn split_packets(size: usize) -> Vec<PacketBuf> {
    (0..PACKETS)
        .map(|index| {
            let mut packet = vec![0x45; size];
            packet[ROUTE_BYTE] = u8::from(index % 2 == 1);
            PacketBuf::from_packet(&packet)
        })
        .collect()
}

/// The splitter sink index for `packet`.
fn route(packet: &PacketBuf) -> usize {
    usize::from(
        packet
            .as_packet()
            .get(ROUTE_BYTE)
            .is_some_and(|byte| byte & 1 == 1),
    )
}

/// A sink that consumes every packet like a device write and counts them, per batch; with
/// `spent` it hands the buffers back through `send_batch_spent`, otherwise it drops them.
struct Writer {
    spent: bool,
    written: watch::Sender<usize>,
}

impl Writer {
    fn write(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>, spent: &mut Vec<PacketBuf>) {
        let count = packets.len();
        for (_, packet) in packets.drain(..) {
            black_box(packet.as_packet());
            if self.spent {
                spent.push(packet);
            }
        }
        self.written.send_modify(|written| *written += count);
    }
}

impl PacketSink for Writer {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        self.send_batch(&mut VecDeque::from([(from, packet)])).await
    }

    fn send_batch(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        self.write(packets, &mut Vec::new());
        std::future::ready(Ok(()))
    }

    fn send_batch_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        self.write(packets, spent);
        std::future::ready(Ok(()))
    }
}

/// Sends every packet in `held` into `sink` one at a time.
async fn send_each(sink: &impl PacketSink, held: &mut Vec<PacketBuf>) {
    while let Some(packet) = held.pop() {
        sink.send(packet, PeerId::new(1)).await.unwrap();
    }
}

/// Sends every packet in `held` into `sink` with one `send_batch`.
async fn send_all(
    sink: &impl PacketSink,
    held: &mut Vec<PacketBuf>,
    queue: &mut VecDeque<(PeerId, PacketBuf)>,
) {
    queue.extend(held.drain(..).map(|packet| (PeerId::new(1), packet)));
    sink.send_batch(queue).await.unwrap();
    assert!(queue.is_empty());
}

/// Reads packets back from `source` into `held` until it holds `until`.
async fn refill(
    source: &mut PipeSource,
    held: &mut Vec<PacketBuf>,
    batch: &mut PacketBatch,
    until: usize,
) {
    while held.len() < until {
        source.recv_batch(batch).await.unwrap();
        held.extend(batch.drain());
    }
}

fn bench_pipe(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("pipe");
    group.throughput(Throughput::Elements(PACKETS as u64));
    for size in SIZES {
        let (sink, mut source) = pipe(PACKETS, 1420);
        let mut held = packets(size);
        let mut batch = PacketBatch::new();
        group.bench_function(format!("send_recv_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    while let Some(packet) = held.pop() {
                        sink.send(packet, PeerId::new(1)).await.unwrap();
                    }
                    while held.len() < PACKETS {
                        source.recv_batch(&mut batch).await.unwrap();
                        held.extend(batch.drain());
                    }
                });
            });
        });
    }
    for size in SIZES {
        let (sink, mut source) = pipe(PACKETS, 1420);
        let mut held = Vec::with_capacity(PACKETS);
        let mut batch = PacketBatch::new();
        group.bench_function(format!("alloc_send_recv_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    for _ in 0..PACKETS {
                        sink.send(sink.alloc(size), PeerId::new(1)).await.unwrap();
                    }
                    while held.len() < PACKETS {
                        source.recv_batch(&mut batch).await.unwrap();
                        held.extend(batch.drain());
                    }
                    source.recycle(&mut held);
                    held.clear();
                });
            });
        });
    }
    group.finish();
}

fn bench_pump(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("pump");
    group.throughput(Throughput::Elements(PACKETS as u64));
    for size in SIZES {
        group.bench_function(format!("pipe_to_pipe_{size}"), |bench| {
            bench.iter_batched(
                || packets(size),
                |held| {
                    runtime.block_on(async {
                        let (input, source) = pipe(PACKETS, 1420);
                        let (sink, mut output) = pipe(PACKETS, 1420);
                        let drain = tokio::spawn(async move {
                            let mut batch = PacketBatch::new();
                            let mut count = 0;
                            while output.recv_batch(&mut batch).await.is_ok() {
                                count += batch.len();
                                batch.clear();
                            }
                            count
                        });
                        let pumping = tokio::spawn(pump(source, sink, PeerId::new(1)));
                        for packet in held {
                            input.send(packet, PeerId::new(1)).await.unwrap();
                        }
                        drop(input);
                        pumping.await.unwrap().unwrap();
                        assert_eq!(drain.await.unwrap(), PACKETS);
                    });
                },
                BatchSize::SmallInput,
            );
        });
    }
    for (name, spent) in [("pipe_to_writer", false), ("pipe_to_writer_spent", true)] {
        for size in SIZES {
            let (input, source) = pipe(PACKETS, 1420);
            let (written, mut counted) = watch::channel(0);
            runtime.spawn(pump(source, Writer { spent, written }, PeerId::new(1)));
            let mut target = 0;
            group.bench_function(format!("{name}_{size}"), |bench| {
                bench.iter(|| {
                    runtime.block_on(async {
                        for _ in 0..PACKETS {
                            input.send(input.alloc(size), PeerId::new(1)).await.unwrap();
                        }
                        target += PACKETS;
                        counted.wait_for(|&n| n >= target).await.unwrap();
                    });
                });
            });
        }
    }
    group.finish();
}

fn bench_splitter(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("splitter");
    group.throughput(Throughput::Elements(PACKETS as u64));
    for size in SIZES {
        for rewrite in [false, true] {
            let (sink0, mut source0) = pipe(PACKETS, 1420);
            let (sink1, mut source1) = pipe(PACKETS, 1420);
            let (name, splitter) = if rewrite {
                let splitter = Splitter::new_map(|_peer, packet| {
                    if let Some(ttl) = packet.as_packet_mut().get_mut(TTL_BYTE) {
                        *ttl = ttl.wrapping_sub(1);
                    }
                    route(packet)
                });
                ("new_map", splitter)
            } else {
                ("new", Splitter::new(|_peer, packet| route(packet)))
            };
            let splitter = splitter.sink(sink0).sink(sink1);
            let mut held = split_packets(size);
            let mut batch = PacketBatch::new();
            group.bench_function(format!("{name}_{size}"), |bench| {
                bench.iter(|| {
                    runtime.block_on(async {
                        send_each(&splitter, &mut held).await;
                        refill(&mut source0, &mut held, &mut batch, PACKETS / 2).await;
                        refill(&mut source1, &mut held, &mut batch, PACKETS).await;
                    });
                });
            });
        }
    }
    group.finish();
}

fn bench_map_sink(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("map_sink");
    group.throughput(Throughput::Elements(PACKETS as u64));
    let keep = |_packet: &mut PacketBuf, _from: PeerId| MapVerdict::Keep;
    for size in SIZES {
        let mut held = packets(size);
        let mut batch = PacketBatch::new();
        let mut queue = VecDeque::new();

        let (sink, mut source) = pipe(PACKETS, 1420);
        let plain = MapSink::new(sink, keep);
        group.bench_function(format!("send_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_each(&plain, &mut held).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
        group.bench_function(format!("send_batch_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_all(&plain, &mut held, &mut queue).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });

        let (sink, mut source) = pipe(PACKETS, 1420);
        let delivered = Arc::new(AtomicU64::new(0));
        let after = MapSink::with_after(sink, keep, move |_packet: &[u8]| {
            delivered.fetch_add(1, Ordering::Relaxed);
        });
        group.bench_function(format!("send_after_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_each(&after, &mut held).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
        group.bench_function(format!("send_batch_after_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_all(&after, &mut held, &mut queue).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
    }
    group.finish();
}

fn bench_swap_sink(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("swap_sink");
    group.throughput(Throughput::Elements(PACKETS as u64));
    for size in SIZES {
        let mut held = packets(size);
        let mut batch = PacketBatch::new();
        let mut queue = VecDeque::new();

        let (bare, mut source) = pipe(PACKETS, 1420);
        group.bench_function(format!("bare_send_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_each(&bare, &mut held).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
        group.bench_function(format!("bare_send_batch_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_all(&bare, &mut held, &mut queue).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });

        let (sink, mut source) = pipe(PACKETS, 1420);
        let swap = SwapSink::new(Some(sink));
        group.bench_function(format!("swap_send_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_each(&swap, &mut held).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
        group.bench_function(format!("swap_send_batch_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_all(&swap, &mut held, &mut queue).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });

        let (sink, mut source) = pipe(PACKETS, 1420);
        // The handle stays alive and unused: the not-aborted path.
        let (sink, _abort) = AbortSink::new(sink);
        let swap = SwapSink::new(Some(sink));
        group.bench_function(format!("swap_abort_send_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_each(&swap, &mut held).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
        group.bench_function(format!("swap_abort_send_batch_{size}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    send_all(&swap, &mut held, &mut queue).await;
                    refill(&mut source, &mut held, &mut batch, PACKETS).await;
                });
            });
        });
    }
    group.finish();
}

criterion::criterion_group!(
    local_graph_benches,
    bench_pipe,
    bench_pump,
    bench_splitter,
    bench_map_sink,
    bench_swap_sink
);
criterion::criterion_main!(local_graph_benches);
