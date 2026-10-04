//! Per-packet cost of the `Masquerade`.
//!
//! - `established/*`: `forward` of a request and `reverse` of its reply on an
//!   established UDP flow (one closure call for the reply's route check),
//!   with 64 B and 1420 B payloads; the checksums are verified and
//!   recomputed.
//! - `new_flow`: `forward` of a request that opens a new flow every time (the
//!   source port changes); old flows expire, so the table stays bounded.

use std::hint::black_box;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nsplane_nat::{Masquerade, MasqueradeConfig, MasqueradeDecision, MasqueradeVerdict};
use nsplane_packet::checksum::transport_checksum_v6;
use nsplane_packet::{FiveTuple, PacketBuf};

const HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaa, 0, 0, 0, 0, 0, 0x10);
const REMOTE: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 0xb, 0xc0a8, 0xb01);
const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 2, 0, 0, 0x6440, 1);

/// The decision closure: every flow is masqueraded.
fn decide() -> impl Fn(&FiveTuple) -> Option<MasqueradeDecision> + Send + Sync + 'static {
    |_| {
        Some(MasqueradeDecision {
            source: SOURCE,
            route: 1,
        })
    }
}

/// An IPv6 UDP packet with `payload` zero bytes and a valid checksum.
fn udp(src: (Ipv6Addr, u16), dst: (Ipv6Addr, u16), payload: usize) -> Vec<u8> {
    let len = u16::try_from(8 + payload).unwrap_or(u16::MAX);
    let mut segment = vec![0; 8 + payload];
    segment[0..2].copy_from_slice(&src.1.to_be_bytes());
    segment[2..4].copy_from_slice(&dst.1.to_be_bytes());
    segment[4..6].copy_from_slice(&len.to_be_bytes());
    let checksum = transport_checksum_v6(src.0, dst.0, 17, &segment);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(&[17, 64]);
    bytes.extend_from_slice(&src.0.octets());
    bytes.extend_from_slice(&dst.0.octets());
    bytes.extend_from_slice(&segment);
    bytes
}

fn established(c: &mut Criterion) {
    let mut group = c.benchmark_group("established");
    for payload in [64, 1420] {
        let masquerade = Masquerade::new(decide(), MasqueradeConfig::default());
        let request = udp((HOST, 10_000), (REMOTE, 53), payload);
        let mut first = PacketBuf::from_packet(&request);
        assert_eq!(masquerade.forward(&mut first), MasqueradeVerdict::Rewritten);
        let token = u16::from_be_bytes([first.as_packet()[40], first.as_packet()[41]]);
        let reply = udp((REMOTE, 53), (SOURCE, token), payload);
        let mut packet = PacketBuf::from_packet(&request);
        group.bench_function(format!("{payload}B"), |b| {
            b.iter(|| {
                packet.as_packet_mut().copy_from_slice(&request);
                let forward = masquerade.forward(black_box(&mut packet));
                packet.as_packet_mut().copy_from_slice(&reply);
                let reverse = masquerade.reverse(black_box(&mut packet));
                (forward, reverse)
            });
        });
    }
    group.finish();
}

fn new_flow(c: &mut Criterion) {
    // A clock that moves 1 ms per reading and a 1 s UDP timeout keep the
    // table bounded: old flows expire and are reclaimed as the default
    // table fills.
    let base = Instant::now();
    let ticks = AtomicU64::new(0);
    let masquerade = Masquerade::with_clock(
        decide(),
        MasqueradeConfig {
            udp_timeout: Duration::from_secs(1),
            ..MasqueradeConfig::default()
        },
        move || base + Duration::from_millis(ticks.fetch_add(1, Ordering::Relaxed)),
    );
    let mut port: u16 = 0;
    c.bench_function("new_flow", |b| {
        b.iter_batched_ref(
            || {
                port = port.wrapping_add(1);
                PacketBuf::from_packet(&udp((HOST, port), (REMOTE, 53), 64))
            },
            |packet| masquerade.forward(black_box(packet)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, established, new_flow);
criterion_main!(benches);
