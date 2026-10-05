#![allow(clippy::unwrap_used, clippy::panic, reason = "benchmark harness")]

//! Throughput of one engine with the crypto worker pool off and on.
//!
//! A hub engine runs with 0 (off), 2 or 4 crypto workers and has `SPOKES` peers, each an
//! engine of its own (pool off) on an in-memory link. One iteration sends `BURST` packets
//! from the hub to every spoke and from every spoke to the hub at once, and waits until all
//! of them are delivered: the hub encrypts and decrypts every packet, while each spoke only
//! handles its own share, so the hub's crypto is the bottleneck. The runtime is
//! multi-threaded, one worker thread per core.
//!
//! The one-peer case links the hub to a single spoke with as many crypto workers as the hub
//! and sends `SPOKES * BURST` packets each way per iteration: one peer's packets spread over
//! the workers.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput};
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, Engine, EngineBuilder,
    EngineHandle, PacketBuf, Path, Peer, PeerId, TransportId,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Spokes, so the work can spread over the workers.
const SPOKES: u8 = 8;
/// Packets per direction and spoke in one iteration. What the hub receives in one iteration
/// fits into its deliver queue, so nothing is dropped.
const BURST: usize = 120;
/// Capacity of every queue and link.
const CAPACITY: usize = 1024;
/// Transport id of every spoke's link to the hub.
const SPOKE_LINK: TransportId = TransportId::new(1);

/// Tunnel address of the node with key seed `seed` (the hub is 1, spokes from 2).
const fn ip(seed: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, seed)
}

/// An IPv4 packet of `len` bytes from `src` to `dst`.
fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet
}

/// One engine and the test ends of its source and sink.
struct Node {
    _engine: Engine,
    handle: EngineHandle,
    seed: u8,
    local: mpsc::Sender<PacketBuf>,
    delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
}

impl Node {
    fn new(seed: u8, transports: Vec<ChannelTransport>, workers: usize) -> Self {
        let (source, local, _mtu) = ChannelSource::new(CAPACITY, 1420);
        let (sink, delivered) = ChannelSink::new(CAPACITY);
        let builder = EngineBuilder::new(source, sink)
            .private_key(StaticSecret::from([seed; 32]))
            .crypto_workers(workers);
        let engine = transports
            .into_iter()
            .fold(builder, EngineBuilder::transport)
            .build()
            .unwrap();
        Self {
            handle: engine.handle(),
            _engine: engine,
            seed,
            local,
            delivered,
        }
    }

    fn public(&self) -> PublicKey {
        PublicKey::from(&StaticSecret::from([self.seed; 32]))
    }

    /// This node as a peer reached on `path`.
    fn as_peer(&self, path: Path) -> Peer {
        Peer {
            allowed_ips: vec![AllowedIp {
                addr: ip(self.seed).into(),
                cidr: 32,
            }],
            path: Some(path),
            ..Peer::new(self.public())
        }
    }
}

fn addr(seed: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], port))
}

const fn at(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// The hub with `workers` crypto workers and `count` peered spokes with `spoke_workers`,
/// with sessions up.
async fn star(count: u8, workers: usize, spoke_workers: usize) -> (Node, Vec<Node>) {
    let mut hub_links = Vec::new();
    let mut spokes = Vec::new();
    for seed in 2..2 + count {
        let (hub_end, spoke_end) = ChannelTransport::pair(
            CAPACITY,
            (TransportId::new(u16::from(seed)), addr(1, u16::from(seed))),
            (SPOKE_LINK, addr(seed, 2000)),
        );
        hub_links.push(hub_end);
        spokes.push(Node::new(seed, vec![spoke_end], spoke_workers));
    }
    let mut hub = Node::new(1, hub_links, workers);
    for spoke in &mut spokes {
        let id = TransportId::new(u16::from(spoke.seed));
        hub.handle
            .add_or_update_peer(spoke.as_peer(at(id, addr(spoke.seed, 2000))))
            .await
            .unwrap();
        spoke
            .handle
            .add_or_update_peer(hub.as_peer(at(SPOKE_LINK, addr(1, u16::from(spoke.seed)))))
            .await
            .unwrap();
        // One packet each way, one after the other, runs the handshake.
        let packet = ipv4_packet(ip(1), ip(spoke.seed), 64);
        hub.local
            .send(PacketBuf::from_packet(&packet))
            .await
            .unwrap();
        spoke.delivered.recv().await.unwrap();
        let packet = ipv4_packet(ip(spoke.seed), ip(1), 64);
        spoke
            .local
            .send(PacketBuf::from_packet(&packet))
            .await
            .unwrap();
        hub.delivered.recv().await.unwrap();
    }
    (hub, spokes)
}

/// Sends `burst` packets of `len` bytes each way between the hub and every spoke and waits
/// for all of them.
async fn burst(hub: &mut Node, spokes: &mut [Node], len: usize, burst: usize) {
    let to_hub = burst * spokes.len();
    let mut senders = Vec::new();
    for spoke in spokes.iter() {
        for (from, to, local) in [
            (1, spoke.seed, hub.local.clone()),
            (spoke.seed, 1, spoke.local.clone()),
        ] {
            let packet = ipv4_packet(ip(from), ip(to), len);
            senders.push(tokio::spawn(async move {
                for _ in 0..burst {
                    local.send(PacketBuf::from_packet(&packet)).await.unwrap();
                }
            }));
        }
    }
    let spoke_receivers = spokes.iter_mut().map(|spoke| async move {
        for _ in 0..burst {
            spoke.delivered.recv().await.unwrap();
        }
    });
    let hub_receiver = async {
        for _ in 0..to_hub {
            hub.delivered.recv().await.unwrap();
        }
    };
    let spokes_done = async {
        for receiver in spoke_receivers {
            receiver.await;
        }
    };
    tokio::join!(hub_receiver, spokes_done);
    for sender in senders {
        sender.await.unwrap();
    }
}

/// Measures `group` on a hub with `count` spokes, `per_spoke` packets each way per spoke and
/// iteration, and with 0, 2 and 4 crypto workers (the spokes with `spoke_workers` of them).
fn bench_star(
    c: &mut Criterion,
    runtime: &Runtime,
    group: &str,
    count: u8,
    per_spoke: usize,
    spoke_workers: impl Fn(usize) -> usize,
) {
    let mut group = c.benchmark_group(group);
    group.measurement_time(Duration::from_secs(5));
    for len in [64, 1420] {
        // Both directions of every spoke.
        let packets = per_spoke * usize::from(count) * 2;
        group.throughput(Throughput::Elements(packets as u64));
        for workers in [0, 2, 4] {
            let (mut hub, mut spokes) =
                runtime.block_on(star(count, workers, spoke_workers(workers)));
            group.bench_with_input(
                BenchmarkId::new(format!("{len}B"), workers),
                &len,
                |b, &len| {
                    b.iter_custom(|iters| {
                        runtime.block_on(async {
                            let start = Instant::now();
                            for _ in 0..iters {
                                burst(&mut hub, &mut spokes, len, per_spoke).await;
                            }
                            start.elapsed()
                        })
                    });
                },
            );
            let drops = runtime.block_on(hub.handle.drop_counters()).unwrap();
            assert!(drops.is_empty(), "the hub dropped packets: {drops:?}");
        }
    }
    group.finish();
}

fn bench_worker_pool(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    bench_star(c, &runtime, "worker_pool", SPOKES, BURST, |_| 0);
    let per_spoke = BURST * usize::from(SPOKES);
    bench_star(
        c,
        &runtime,
        "worker_pool_one_peer",
        1,
        per_spoke,
        |workers| workers,
    );
}

criterion::criterion_group!(worker_pool, bench_worker_pool);
criterion::criterion_main!(worker_pool);
