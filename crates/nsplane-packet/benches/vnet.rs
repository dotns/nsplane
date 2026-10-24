#![allow(clippy::unwrap_used, reason = "benchmark harness")]

//! Virtio-net segmentation: splitting a 64 KiB TCP over IPv4 super-packet at `gso_size` 1380
//! into ~47 segments.

use criterion::{Criterion, Throughput};
use nsplane_packet::vnet::{VirtioNetHdr, segment};
use nsplane_packet::{PacketBatch, PacketPool};

/// TCP payload bytes per segment (MTU 1420 minus IPv4 and TCP headers).
const GSO_SIZE: u16 = 1380;
/// IPv4 and TCP header bytes.
const HLEN: usize = 40;

/// A 65535-byte TCP over IPv4 super-packet and its virtio header, as the kernel hands it over.
fn super_packet() -> (VirtioNetHdr, Vec<u8>) {
    let mut p = vec![0u8; 65535];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&65535u16.to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&443u16.to_be_bytes());
    p[24..28].copy_from_slice(&1u32.to_be_bytes());
    p[32] = 5 << 4;
    p[33] = 0x10;
    p[34..36].copy_from_slice(&512u16.to_be_bytes());
    for (i, byte) in p[HLEN..].iter_mut().enumerate() {
        *byte = i.to_le_bytes()[0];
    }
    let hdr = VirtioNetHdr {
        flags: VirtioNetHdr::F_NEEDS_CSUM,
        gso_type: VirtioNetHdr::GSO_TCPV4,
        hdr_len: 40,
        gso_size: GSO_SIZE,
        csum_start: 20,
        csum_offset: 16,
    };
    (hdr, p)
}

fn bench_vnet(c: &mut Criterion) {
    let (hdr, packet) = super_packet();
    let mut group = c.benchmark_group("vnet");
    group.throughput(Throughput::Bytes(packet.len() as u64));
    group.bench_function("segment_tcpv4_64k", |b| {
        let mut pool = PacketPool::new(64);
        let mut out = PacketBatch::new();
        b.iter(|| {
            let next = segment(
                &hdr,
                &packet,
                0,
                HLEN + usize::from(GSO_SIZE),
                &mut pool,
                &mut out,
            )
            .unwrap();
            for buf in out.drain() {
                pool.put(buf);
            }
            next
        });
    });
    group.finish();
}

criterion::criterion_group!(vnet_benches, bench_vnet);
criterion::criterion_main!(vnet_benches);
