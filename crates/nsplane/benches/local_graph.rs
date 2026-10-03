#![allow(clippy::unwrap_used, reason = "benchmark harness")]

//! Local-side graph primitives on a current-thread runtime, per packet, for 64 B and
//! 1420 B packets: `pipe` sends a batch of packets into a pipe and reads them back with
//! `recv_batch`; `pump` moves the packets from one pipe into another with `pump` while a
//! task drains the second pipe.

use criterion::{BatchSize, Criterion, Throughput};
use nsplane::{PacketBatch, PacketBuf, PacketSink, PacketSource, PeerId, pipe, pump};

/// Packets per iteration.
const PACKETS: usize = 1024;

/// Packet sizes: a minimal packet and a full one at MTU 1420.
const SIZES: [usize; 2] = [64, 1420];

fn packets(size: usize) -> Vec<PacketBuf> {
    (0..PACKETS)
        .map(|_| PacketBuf::from_packet(&vec![0x45; size]))
        .collect()
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
    group.finish();
}

criterion::criterion_group!(local_graph_benches, bench_pipe, bench_pump);
criterion::criterion_main!(local_graph_benches);
