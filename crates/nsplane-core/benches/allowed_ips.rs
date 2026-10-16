//! `AllowedIps::find` on IPv4 and IPv6 tables of 1, 16, 1 k and 10 k entries, for addresses
//! inside an inserted prefix (`hit`), outside every prefix (`miss`) and next to an inserted prefix
//! but outside every prefix (`near`: the prefix with its last network bit flipped, so a lookup
//! descends as far as the prefix before it fails); each case cycles over
//! `LOOKUPS` addresses and reports the time of one `find`. The write cases report building a
//! 10 k table with `insert` in one configuration change (`build`) and 1 k and 10 k tables in one
//! change per network (`build_per_change`), one `insert` and `remove_network` of a new prefix on
//! a 10 k table, each its own change (`insert_remove`; `insert_remove_new_len` with a /1, a
//! prefix length the table does not use yet), removing one value's entries from a 10 k table
//! with `remove` (`remove_value`), and emptying a 10 k table of 1 k values (10 networks each)
//! one value per change (`remove_peer_per_change`). A change ends with `commit`, see
//! [`Commit`].
//!
//! Tables come from a fixed-seed generator: prefixes of mixed length (IPv4 /8../32, IPv6
//! /32../128, a quarter of them host routes), all with the top address bit clear, so an
//! address with that bit set is a guaranteed miss. A duplicate prefix overwrites the earlier one.

#[path = "../src/allowed_ips.rs"]
mod allowed_ips;

use std::collections::HashSet;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Instant;

use allowed_ips::AllowedIps;
use criterion::{BatchSize, Criterion, SamplingMode};

/// Addresses each lookup case cycles over.
const LOOKUPS: usize = 1024;
/// Distinct values in a table; entry `i` stores `i % VALUES`.
const VALUES: u32 = 100;
/// Table sizes of the lookup cases and their ids.
const SIZES: [(usize, &str); 4] = [(1, "1"), (16, "16"), (1000, "1k"), (10_000, "10k")];
/// Table size of the write cases.
const WRITE_SIZE: usize = 10_000;
/// Networks per value in `remove_peer_per_change`.
const PEER_NETWORKS: usize = 10;
/// The top address bit: clear in every inserted prefix, set in every miss address.
const TOP_BIT: u128 = 1 << 127;

/// The end of a configuration change, on both sides of an A/B against v0.14.1.
///
/// Where the table defers its rebuilds, the inherent `AllowedIps::commit` shadows this method;
/// v0.14.1 has no commit (its writes take effect at once), so there this default runs. It
/// returns the family rebuilds the table has run, none for v0.14.1. `pub` because only one side
/// calls it.
pub trait Commit {
    fn commit(&mut self) -> usize {
        0
    }
}

impl<D> Commit for AllowedIps<D> {}

/// An address family; addresses are held left-aligned in a `u128`.
#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    const fn id(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    /// Shortest and longest generated prefix length.
    const fn lengths(self) -> (u8, u8) {
        match self {
            Self::V4 => (8, 32),
            Self::V6 => (32, 128),
        }
    }

    fn addr(self, bits: u128) -> IpAddr {
        let b = bits.to_be_bytes();
        match self {
            Self::V4 => IpAddr::from([b[0], b[1], b[2], b[3]]),
            Self::V6 => IpAddr::from(b),
        }
    }
}

/// splitmix64.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bits(&mut self) -> u128 {
        (u128::from(self.next()) << 64) | u128::from(self.next())
    }

    /// An index below `len`.
    fn below(&mut self, len: usize) -> usize {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        usize::try_from(self.next() % len).unwrap_or(0)
    }
}

/// The network bits of a left-aligned prefix of `len` bits.
fn mask(len: u8) -> u128 {
    u128::MAX << (128 - u32::from(len))
}

/// `n` prefixes `(address, length)` with the top bit clear.
fn prefixes(family: Family, n: usize, rng: &mut Rng) -> Vec<(u128, u8)> {
    let (min, max) = family.lengths();
    (0..n)
        .map(|_| {
            let r = rng.next().to_le_bytes();
            let len = if r[0].is_multiple_of(4) {
                max
            } else {
                min + r[1] % (max - min + 1)
            };
            (rng.bits() & !TOP_BIT & mask(len), len)
        })
        .collect()
}

fn value(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX) % VALUES
}

/// A table of `prefixes` built in one configuration change: one rebuild at most.
fn build(family: Family, prefixes: &[(u128, u8)]) -> AllowedIps<u32> {
    let mut table = AllowedIps::new();
    for (i, &(net, len)) in prefixes.iter().enumerate() {
        table.insert(family.addr(net), len, value(i));
    }
    assert!(table.commit() <= 1);
    table
}

/// A table of `prefixes` built in one configuration change per network.
fn build_per_change(family: Family, prefixes: &[(u128, u8)]) -> AllowedIps<u32> {
    let mut table = AllowedIps::new();
    for (i, &(net, len)) in prefixes.iter().enumerate() {
        table.insert(family.addr(net), len, value(i));
        table.commit();
    }
    table
}

/// Checks that every prefix is in `table` and that `table` holds no other network.
fn check(family: Family, table: &AllowedIps<u32>, prefixes: &[(u128, u8)]) {
    assert!(!table.is_empty());
    let networks: HashSet<_> = prefixes
        .iter()
        .map(|&(net, len)| (family.addr(net), len))
        .collect();
    for &(net, len) in &networks {
        assert!(table.get(net, len).is_some());
    }
    assert!(
        table
            .iter()
            .all(|(_, net, len)| networks.contains(&(net, len)))
    );
    assert_eq!(table.iter().count(), networks.len());
}

/// Up to `LOOKUPS` addresses next to the prefixes (last network bit flipped, host bits random)
/// that `table` does not match.
fn near(
    family: Family,
    table: &AllowedIps<u32>,
    prefixes: &[(u128, u8)],
    rng: &mut Rng,
) -> Vec<IpAddr> {
    (0..LOOKUPS * 64)
        .filter_map(|_| {
            let (net, len) = prefixes[rng.below(prefixes.len())];
            let flipped = net ^ (1 << (128 - u32::from(len)));
            let addr = family.addr(flipped | (rng.bits() & !mask(len)));
            table.find(addr).is_none().then_some(addr)
        })
        .take(LOOKUPS)
        .collect()
}

/// `LOOKUPS` addresses inside the prefixes (host bits random) and `LOOKUPS` outside them.
fn addresses(family: Family, prefixes: &[(u128, u8)], rng: &mut Rng) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let hits = (0..LOOKUPS)
        .map(|_| {
            let (net, len) = prefixes[rng.below(prefixes.len())];
            family.addr(net | (rng.bits() & !mask(len)))
        })
        .collect();
    let misses = (0..LOOKUPS)
        .map(|_| family.addr(rng.bits() | TOP_BIT))
        .collect();
    (hits, misses)
}

fn find(c: &mut Criterion) {
    let mut rng = Rng(0x6e73_706c_616e_6531);
    let mut group = c.benchmark_group("allowed_ips");
    for family in [Family::V4, Family::V6] {
        for (size, size_id) in SIZES {
            let prefixes = prefixes(family, size, &mut rng);
            let table = build(family, &prefixes);
            check(family, &table, &prefixes);
            let (hits, misses) = addresses(family, &prefixes, &mut rng);
            assert!(hits.iter().all(|&a| table.find(a).is_some()));
            assert!(misses.iter().all(|&a| table.find(a).is_none()));
            let near = near(family, &table, &prefixes, &mut rng);
            let cases = [("hit", &hits), ("miss", &misses), ("near", &near)];
            for (kind, addrs) in cases.into_iter().filter(|(_, addrs)| !addrs.is_empty()) {
                let id = format!("find/{}/{kind}/{size_id}", family.id());
                group.bench_function(id, |b| {
                    b.iter_custom(|iters| {
                        let begin = Instant::now();
                        for (&addr, _) in addrs.iter().cycle().zip(0..iters) {
                            black_box(table.find(black_box(addr)));
                        }
                        begin.elapsed()
                    });
                });
            }
        }
    }

    for family in [Family::V4, Family::V6] {
        let prefixes = prefixes(family, WRITE_SIZE, &mut rng);
        group.bench_function(format!("build/{}/10k", family.id()), |b| {
            b.iter_with_large_drop(|| build(family, black_box(&prefixes)));
        });
        // Up to a rebuild per network where every write rebuilds: seconds per build, so ten
        // single builds.
        group.sample_size(10).sampling_mode(SamplingMode::Flat);
        for (n, id) in [(1000, "1k"), (WRITE_SIZE, "10k")] {
            let prefixes = &prefixes[..n];
            group.bench_function(format!("build_per_change/{}/{id}", family.id()), |b| {
                b.iter_with_large_drop(|| build_per_change(family, black_box(prefixes)));
            });
            check(family, &build_per_change(family, prefixes), prefixes);
        }
        // Up to a rebuild per value where every remove by value rebuilds.
        group.bench_function(format!("remove_peer_per_change/{}/10k", family.id()), |b| {
            b.iter_batched(
                || {
                    let mut table = AllowedIps::new();
                    for (i, &(net, len)) in prefixes.iter().enumerate() {
                        let peer = u32::try_from(i / PEER_NETWORKS).unwrap_or(u32::MAX);
                        table.insert(family.addr(net), len, peer);
                    }
                    table.commit();
                    table
                },
                |mut table| {
                    for peer in 0..WRITE_SIZE / PEER_NETWORKS {
                        let peer = u32::try_from(peer).unwrap_or(u32::MAX);
                        table.remove(&|&v| v == black_box(peer));
                        table.commit();
                    }
                    assert!(table.is_empty());
                    table
                },
                BatchSize::LargeInput,
            );
        });
        group.sample_size(100).sampling_mode(SamplingMode::Auto);

        let (_, max) = family.lengths();
        let new = family.addr(rng.bits() | TOP_BIT);
        let mut table = build(family, &prefixes);
        group.bench_function(format!("insert_remove/{}/10k", family.id()), |b| {
            b.iter(|| {
                black_box(table.insert(black_box(new), max, VALUES));
                black_box(table.commit());
                black_box(table.remove_network(black_box(new), max));
                black_box(table.commit());
            });
        });
        group.bench_function(format!("insert_remove_new_len/{}/10k", family.id()), |b| {
            b.iter(|| {
                black_box(table.insert(black_box(new), 1, VALUES));
                black_box(table.commit());
                black_box(table.remove_network(black_box(new), 1));
                black_box(table.commit());
            });
        });
        check(family, &table, &prefixes);
        table.clear();
        assert!(table.is_empty());

        group.bench_function(format!("remove_value/{}/10k", family.id()), |b| {
            b.iter_batched(
                || build(family, &prefixes),
                |mut table| {
                    table.remove(&|&v| v == black_box(0));
                    table.commit();
                    table
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion::criterion_group!(benches, find);
criterion::criterion_main!(benches);
