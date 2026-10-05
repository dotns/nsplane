#![allow(clippy::unwrap_used, reason = "benchmark harness")]

//! `UdpTransport` on the loopback interface: a batch of 64 datagrams of 1420 bytes sent with
//! `send_batch` and received with `recv_batch`, with segmentation offload on (where the
//! kernel supports it: one segmented send and one coalesced read) and off (batched without
//! offload where the platform has the calls: `sendmmsg` for the run, `recvmmsg` of up to 16
//! datagrams per call; one system call per datagram each way elsewhere). The `_side`
//! variants attach a side channel to the receiver that classifies nothing, to show what
//! classifying every datagram costs.

use std::collections::VecDeque;
use std::net::SocketAddr;

use criterion::{Criterion, Throughput};
use nsplane::{Ecn, MAX_BATCH, PacketBuf, Path, Transport, TransportId, UdpTransport};

/// Bytes per datagram: a full WireGuard datagram at MTU 1420.
const SIZE: usize = 1420;

fn bench_udp(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let mut group = c.benchmark_group("udp_loopback");
    group.throughput(Throughput::Elements(MAX_BATCH as u64));
    for (offload, side) in [(false, false), (true, false), (false, true), (true, true)] {
        let localhost: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let a = UdpTransport::bind(TransportId::new(1), localhost).unwrap();
        let b = UdpTransport::bind(TransportId::new(2), localhost).unwrap();
        let b = if side {
            b.with_side_channel(|_| false, 1).0
        } else {
            b
        };
        a.set_offload(offload).unwrap();
        b.set_offload(offload).unwrap();
        let to = Path {
            transport: a.id(),
            addr: b.local_addr(),
            ecn: Ecn::NotEct,
        };
        let batch: Vec<_> = (0..MAX_BATCH)
            .map(|_| (to, PacketBuf::from_packet(&[0x5a; SIZE])))
            .collect();
        let mut buf = PacketBuf::with_capacity(65_535);
        let mut received = VecDeque::with_capacity(MAX_BATCH);
        let name = if offload { "offload_on" } else { "offload_off" };
        let suffix = if side { "_side" } else { "" };
        group.bench_function(format!("batch_64x{SIZE}_{name}{suffix}"), |bench| {
            bench.iter(|| {
                runtime.block_on(async {
                    let (mut sent, mut failed) = (0, 0);
                    a.send_batch(&batch, &mut sent, &mut failed).await.unwrap();
                    let mut count = 0;
                    while count < MAX_BATCH {
                        received.clear();
                        b.recv_batch(&mut buf, &mut received).await.unwrap();
                        count += received.len();
                    }
                });
            });
        });
    }
    group.finish();
}

criterion::criterion_group!(udp_benches, bench_udp);
criterion::criterion_main!(udp_benches);
