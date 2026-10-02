#![allow(clippy::unwrap_used, clippy::panic, reason = "benchmark harness")]

//! Transport data path of the `Core`, comparable with boringtun's `data_path` bench.
//!
//! Two references run next to the core: `tunn_round_trip`, a bare `Tunn` round trip in place
//! as in boringtun's `round_trip_in_place`, and `device_equivalent_round_trip`, the same round
//! trip plus the cryptokey routing a device does per packet (allowed-IP lookup of the
//! destination on send, source check on receive) on the core's own allowed-IP table.

// The core's allowed-IP table is crate-private: compile its source into the bench.
#[allow(dead_code, reason = "the bench uses only the lookups of the table")]
#[path = "../../src/allowed_ips.rs"]
mod allowed_ips;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use nstun_core::noise::{DATA_HEADER_SZ, Tunn, TunnResult};
use nstun_core::x25519::{PublicKey, StaticSecret};
use nstun_core::{
    AllowedIp, ConfigChange, Core, CoreConfig, Ecn, Input, Output, PacketBuf, Path, PeerConfig,
    PeerId, TransportId,
};
use rand_core::OsRng;

use crate::allowed_ips::AllowedIps;

/// Capacity of the packet buffers: room for any bench packet and its WireGuard overhead.
const BUF_CAPACITY: usize = 2048;

/// Path of core `i` (0 or 1).
fn path(i: u8) -> Path {
    Path {
        transport: TransportId::new(u16::from(i)),
        addr: SocketAddr::from((Ipv4Addr::new(192, 0, 2, i + 1), 51820)),
        ecn: Ecn::NotEct,
    }
}

/// Tunnel address of core `i` (0 or 1).
const fn ip4(i: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, i + 1)
}

/// A core holding `key`, with `peer` reachable at `path(j)` and owning `ip4(j)`.
fn core(key: StaticSecret, peer: PublicKey, j: u8, now: Instant) -> Core {
    let mut core = Core::new(CoreConfig {
        private_key: Some(key),
        ..CoreConfig::default()
    });
    let mut config = PeerConfig::new(peer);
    config.allowed_ips = vec![AllowedIp {
        addr: ip4(j).into(),
        cidr: 32,
    }];
    config.path = Some(path(j));
    core.handle_input(Input::Config(ConfigChange::AddOrUpdatePeer(config)), now);
    core
}

/// Moves datagrams between the two cores until none is left; returns how many were delivered.
fn pump(cores: &mut [Core; 2], now: Instant) -> usize {
    let mut delivered = 0;
    loop {
        let mut in_flight = Vec::new();
        for (i, core) in cores.iter_mut().enumerate() {
            while let Some(output) = core.poll_output() {
                match output {
                    Output::Transmit { data, .. } => in_flight.push((i, data)),
                    Output::Deliver { packet, .. } => {
                        delivered += 1;
                        core.recycle(packet);
                    }
                    Output::Event(_) => {}
                }
            }
        }
        if in_flight.is_empty() {
            return delivered;
        }
        for (from, mut data) in in_flight {
            let from_path = path(u8::try_from(from).unwrap());
            let to = &mut cores[1 - from];
            to.handle_input(
                Input::Datagram {
                    path: from_path,
                    data: &mut data,
                },
                now,
            );
            to.recycle(data);
        }
    }
}

/// A pair of cores with an established session, on the real clock.
fn connected_pair() -> (Core, Core) {
    let now = Instant::now();
    let a_key = StaticSecret::random_from_rng(OsRng);
    let b_key = StaticSecret::random_from_rng(OsRng);
    let (a_pub, b_pub) = (PublicKey::from(&a_key), PublicKey::from(&b_key));
    let mut cores = [core(a_key, b_pub, 1, now), core(b_key, a_pub, 0, now)];
    let peer = cores[0].peer_id(&b_pub).unwrap();
    cores[0].force_handshake(peer, None, now);
    pump(&mut cores, now);
    // A packet from each side proves the session is up both ways.
    for i in 0..2u8 {
        let packet = ipv4_packet(ip4(i), ip4(1 - i), 64);
        cores[usize::from(i)].handle_input(
            Input::Local {
                packet: PacketBuf::from_packet(&packet),
            },
            now,
        );
        assert_eq!(pump(&mut cores, now), 1, "session not established");
    }
    cores.into()
}

/// A pair of tunnels with an established session, as in boringtun's `data_path` bench.
fn connected_tunnels() -> (Tunn, Tunn) {
    let a_key = StaticSecret::random_from_rng(OsRng);
    let b_key = StaticSecret::random_from_rng(OsRng);
    let (a_pub, b_pub) = (PublicKey::from(&a_key), PublicKey::from(&b_key));
    let mut a = Tunn::new(a_key, b_pub, None, None, 1, None);
    let mut b = Tunn::new(b_key, a_pub, None, None, 2, None);

    let mut buf = vec![0u8; BUF_CAPACITY];
    let TunnResult::WriteToNetwork(init) = a.format_handshake_initiation(&mut buf, false) else {
        panic!("handshake initiation");
    };
    let init = init.to_vec();
    let TunnResult::WriteToNetwork(resp) = b.decapsulate(None, &init, &mut buf) else {
        panic!("handshake response");
    };
    let resp = resp.to_vec();
    let TunnResult::WriteToNetwork(keepalive) = a.decapsulate(None, &resp, &mut buf) else {
        panic!("keepalive");
    };
    let keepalive = keepalive.to_vec();
    assert!(matches!(
        b.decapsulate(None, &keepalive, &mut buf),
        TunnResult::Done
    ));
    (a, b)
}

/// The allowed-IP table of core `i`: its peer owns `ip4(1 - i)/32`.
fn routes(i: u8) -> AllowedIps<PeerId> {
    let mut table = AllowedIps::new();
    table.insert(ip4(1 - i).into(), 32, PeerId::new(1));
    table
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

/// Writes `packet` into `buf`; stands in for the TUN read into the buffer.
fn fill(buf: &mut PacketBuf, packet: &[u8]) {
    buf.set_len(packet.len());
    buf.as_packet_mut().copy_from_slice(packet);
}

/// Seals `buf` on `tx` and returns the datagram.
fn encapsulate(tx: &mut Core, buf: PacketBuf, now: Instant) -> PacketBuf {
    tx.handle_input(Input::Local { packet: buf }, now);
    let Some(Output::Transmit { data, .. }) = tx.poll_output() else {
        panic!("encapsulate");
    };
    data
}

/// Opens `data` on `rx`, recycles the delivered packet and leaves a pooled buffer in `data`.
fn decapsulate(rx: &mut Core, data: &mut PacketBuf, now: Instant) {
    rx.handle_input(
        Input::Datagram {
            path: path(0),
            data,
        },
        now,
    );
    let Some(Output::Deliver { packet, .. }) = rx.poll_output() else {
        panic!("decapsulate");
    };
    rx.recycle(packet);
}

fn bench_data_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_path");
    for len in [64, 1420] {
        let packet = ipv4_packet(ip4(0), ip4(1), len);
        group.throughput(Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::new("tunn_round_trip", len), &packet, |b, p| {
            let (mut tx, mut rx) = connected_tunnels();
            let mut buf = vec![0u8; BUF_CAPACITY];
            b.iter(|| {
                // Stands in for the TUN read into the buffer.
                buf[DATA_HEADER_SZ..DATA_HEADER_SZ + p.len()].copy_from_slice(p);
                let TunnResult::WriteToNetwork(datagram) =
                    tx.encapsulate_in_place(&mut buf, p.len())
                else {
                    panic!("encapsulate");
                };
                let n = datagram.len();
                assert!(matches!(
                    rx.decapsulate_in_place(None, &mut buf, n),
                    TunnResult::WriteToTunnelV4(..)
                ));
            });
        });

        group.bench_with_input(
            BenchmarkId::new("device_equivalent_round_trip", len),
            &packet,
            |b, p| {
                let (mut tx, mut rx) = connected_tunnels();
                let (tx_routes, rx_routes) = (routes(0), routes(1));
                let peer = PeerId::new(1);
                let mut buf = vec![0u8; BUF_CAPACITY];
                b.iter(|| {
                    buf[DATA_HEADER_SZ..DATA_HEADER_SZ + p.len()].copy_from_slice(p);
                    let packet = &buf[DATA_HEADER_SZ..DATA_HEADER_SZ + p.len()];
                    let dst = Tunn::dst_address(packet).unwrap();
                    assert_eq!(tx_routes.find(dst), Some(&peer));
                    let TunnResult::WriteToNetwork(datagram) =
                        tx.encapsulate_in_place(&mut buf, p.len())
                    else {
                        panic!("encapsulate");
                    };
                    let n = datagram.len();
                    let TunnResult::WriteToTunnelV4(_, src) =
                        rx.decapsulate_in_place(None, &mut buf, n)
                    else {
                        panic!("decapsulate");
                    };
                    assert_eq!(rx_routes.find(IpAddr::V4(src)), Some(&peer));
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("core_round_trip", len), &packet, |b, p| {
            let (mut tx, mut rx) = connected_pair();
            let now = Instant::now();
            let mut slot = Some(PacketBuf::with_capacity(BUF_CAPACITY));
            b.iter(|| {
                let mut buf = slot.take().unwrap();
                fill(&mut buf, p);
                let mut data = encapsulate(&mut tx, buf, now);
                decapsulate(&mut rx, &mut data, now);
                // The buffer the receiver left behind carries the next packet.
                slot = Some(data);
            });
        });

        group.bench_with_input(
            BenchmarkId::new("core_encapsulate", len),
            &packet,
            |b, p| {
                let (mut tx, _rx) = connected_pair();
                let now = Instant::now();
                let mut slot = Some(PacketBuf::with_capacity(BUF_CAPACITY));
                b.iter(|| {
                    let mut buf = slot.take().unwrap();
                    fill(&mut buf, p);
                    // The datagram's buffer carries the next packet.
                    slot = Some(encapsulate(&mut tx, buf, now));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("core_decapsulate", len),
            &packet,
            |b, p| {
                let (mut tx, mut rx) = connected_pair();
                let now = Instant::now();
                b.iter_batched(
                    || {
                        let mut buf = PacketBuf::with_capacity(BUF_CAPACITY);
                        fill(&mut buf, p);
                        encapsulate(&mut tx, buf, now)
                    },
                    |mut data| {
                        decapsulate(&mut rx, &mut data, now);
                        data
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion::criterion_group!(data_path, bench_data_path);
criterion::criterion_main!(data_path);
