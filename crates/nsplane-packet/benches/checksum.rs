//! `checksum::internet_checksum` at 20 B (an IPv4 header), 64 B and 1420 B (a full MTU),
//! next to the previous 16-bit word loop as the baseline.
//!
//! No harness crate: each case reports the best mean of several timed rounds, in ns per call.

use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

use nsplane_packet::checksum::internet_checksum;

/// Calls per timed round.
const ITERS: u32 = 1_000_000;
/// Timed rounds per case; the fastest is reported.
const ROUNDS: usize = 15;

/// The previous implementation: big-endian 16-bit words, odd trailing byte padded with zero.
fn internet_checksum_16(data: &[u8]) -> u16 {
    let (words, tail) = data.as_chunks::<2>();
    let tail = match tail {
        [last] => u64::from(u16::from_be_bytes([*last, 0])),
        _ => 0,
    };
    let mut acc = words
        .iter()
        .fold(tail, |acc, word| acc + u64::from(u16::from_be_bytes(*word)));
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    let [.., hi, lo] = acc.to_be_bytes();
    !u16::from_be_bytes([hi, lo])
}

/// Best mean time per call of `f` over `data`, in ns.
fn time(f: fn(&[u8]) -> u16, data: &[u8]) -> f64 {
    (0..ROUNDS)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..ITERS {
                black_box(f(black_box(data)));
            }
            start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS)
        })
        .fold(f64::INFINITY, f64::min)
}

fn main() -> std::io::Result<()> {
    let data: Vec<u8> = (0..1420u32)
        .map(|i| i.wrapping_mul(131).to_le_bytes()[0])
        .collect();
    let mut out = std::io::stdout().lock();
    for len in [20, 64, 1420] {
        let data = &data[..len];
        assert_eq!(internet_checksum(data), internet_checksum_16(data));
        let words_16 = time(internet_checksum_16, data);
        let words_32 = time(internet_checksum, data);
        writeln!(
            out,
            "checksum/{len:>4} B: 16-bit {words_16:8.2} ns, current {words_32:8.2} ns, {:.2}x",
            words_16 / words_32
        )?;
    }
    Ok(())
}
