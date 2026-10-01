#![allow(clippy::unwrap_used, clippy::panic, reason = "benchmark harness")]

//! Copying versus in-place transport data path of `Tunn`.

use boringtun::noise::{DATA_HEADER_SZ, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use criterion::{BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;

/// A pair of tunnels with an established session.
fn connected_pair() -> (Tunn, Tunn) {
    let a_key = StaticSecret::random_from_rng(OsRng);
    let b_key = StaticSecret::random_from_rng(OsRng);
    let (a_pub, b_pub) = (PublicKey::from(&a_key), PublicKey::from(&b_key));
    let mut a = Tunn::new(a_key, b_pub, None, None, 1, None);
    let mut b = Tunn::new(b_key, a_pub, None, None, 2, None);

    let mut buf = vec![0u8; 2048];
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

/// An IPv4 packet of `len` bytes.
fn ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    packet
}

fn bench_data_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_path");
    for len in [64, 1420] {
        let packet = ipv4_packet(len);
        group.throughput(Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::new("round_trip_copy", len), &packet, |b, p| {
            let (mut tx, mut rx) = connected_pair();
            let mut wire = vec![0u8; 2048];
            let mut out = vec![0u8; 2048];
            b.iter(|| {
                let TunnResult::WriteToNetwork(datagram) = tx.encapsulate(p, &mut wire) else {
                    panic!("encapsulate");
                };
                assert!(matches!(
                    rx.decapsulate(None, datagram, &mut out),
                    TunnResult::WriteToTunnelV4(..)
                ));
            });
        });

        group.bench_with_input(
            BenchmarkId::new("round_trip_in_place", len),
            &packet,
            |b, p| {
                let (mut tx, mut rx) = connected_pair();
                let mut buf = vec![0u8; 2048];
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
            },
        );
    }
    group.finish();
}

criterion::criterion_group!(data_path, bench_data_path);
criterion::criterion_main!(data_path);
