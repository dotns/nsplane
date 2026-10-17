//! Nested LAN prefixes ([`TranslationTableBuilder::nested_lans`]): the
//! flattening into segments, the exact addresses left out, the reverse
//! check, and a randomized comparison of both modes with a naive reference.

use super::*;

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn lan(lan4: &str, len4: u8, lan6: &str, peer: Option<u32>) -> LanPrefix {
    LanPrefix {
        lan4: (v4(lan4), len4),
        lan6: (v6(lan6), LAN6_PREFIX_LEN),
        peer: peer.map(PeerId::new),
    }
}

/// The mapping of peer `n`, with `eam4`.
fn mapping(n: u16, eam4: Option<Ipv4Addr>) -> PeerMapping {
    PeerMapping {
        peer6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 0),
        eam6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 1),
        local6: Some(Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, n)),
        eam4,
    }
}

fn own(eam4: &str) -> SelfMapping {
    SelfMapping {
        eam4: v4(eam4),
        eam6: v6("fd00::ff:1"),
    }
}

fn nested() -> TranslationTableBuilder {
    TranslationTable::builder().nested_lans()
}

fn err(builder: TranslationTableBuilder) -> TableError {
    builder.build().unwrap_err()
}

const fn peer(n: u32) -> PeerId {
    PeerId::new(n)
}

/// The owners (by `lan4` network and length) of the table's segments, in order.
fn owners(table: &TranslationTable) -> Vec<(Ipv4Addr, u8)> {
    table
        .lans
        .iter()
        .map(|segment| (Ipv4Addr::from_bits(segment.lan.start4), segment.lan.len4))
        .collect()
}

#[test]
fn nested_lans_is_off_by_default() {
    assert!(!TranslationTable::builder().build().unwrap().nested_lans());
    assert!(!TranslationTable::default().nested_lans());
    assert!(nested().build().unwrap().nested_lans());
}

#[test]
fn the_whole_space_alone() {
    let table = nested()
        .lan(lan("0.0.0.0", 0, "fd64:9::", Some(1)))
        .build()
        .unwrap();
    assert_eq!(table.lans.len(), 1);
    for addr in ["0.0.0.0", "10.1.2.3", "255.255.255.255"] {
        let (addr6, owner) = table.lan4_to_lan6(v4(addr)).unwrap();
        assert_eq!(
            addr6.to_bits(),
            (0xfd64_0009_u128 << 96) | u128::from(v4(addr).to_bits())
        );
        assert_eq!(owner, Some(peer(1)));
        assert_eq!(table.lan6_to_lan4(addr6), Some((v4(addr), owner)));
    }
}

#[test]
fn a_32_inside_the_whole_space() {
    let table = nested()
        .lan(lan("0.0.0.0", 0, "fd64:1::", Some(1)))
        .lan(lan("203.0.113.9", 32, "fd64:2::", Some(2)))
        .build()
        .unwrap();
    assert_eq!(table.lans.len(), 3);
    assert_eq!(
        table.lan4_to_lan6(v4("203.0.113.9")),
        Some((v6("fd64:2::cb00:7109"), Some(peer(2))))
    );
    for addr in ["203.0.113.8", "203.0.113.10", "0.0.0.0", "255.255.255.255"] {
        assert_eq!(
            table.lan4_to_lan6(v4(addr)).unwrap().1,
            Some(peer(1)),
            "{addr}"
        );
    }
    // The /32 claimed under the /0's base, and outside the /32.
    assert!(table.lan6_to_lan4(v6("fd64:1::cb00:7109")).is_none());
    assert!(table.lan6_to_lan4(v6("fd64:2::cb00:7108")).is_none());
    assert_eq!(
        table.lan6_to_lan4(v6("fd64:2::cb00:7109")),
        Some((v4("203.0.113.9"), Some(peer(2))))
    );
    assert_eq!(
        table.lan6_to_lan4(v6("fd64:1::cb00:710a")),
        Some((v4("203.0.113.10"), Some(peer(1))))
    );
}

#[test]
fn exact_addresses_are_holes_in_a_whole_space_and_a_24() {
    for (prefix, len4) in [("0.0.0.0", 0), ("10.9.1.0", 24)] {
        let base = "fd64:5::";
        let builder = TranslationTable::builder()
            .self_mapping(own("10.9.1.1"))
            .peer(PeerId::new(1), mapping(1, Some(v4("10.9.1.2"))))
            .peer_with_peer6_eam4(PeerId::new(2), mapping(2, None), v4("10.9.1.255"))
            .lan(lan(prefix, len4, base, Some(3)));
        // Rejected without nesting, as in 0.14.2.
        assert_eq!(
            err(builder.clone()),
            TableError::Lan4Overlap(v4(prefix), len4),
            "/{len4}"
        );
        let table = builder.nested_lans().build().unwrap();
        for exact in ["10.9.1.1", "10.9.1.2", "10.9.1.255"] {
            let exact = v4(exact);
            assert!(table.lan4_to_lan6(exact).is_none(), "{exact}/{len4}");
            let claimed = Ipv6Addr::from_bits(v6(base).to_bits() | u128::from(exact.to_bits()));
            assert!(table.lan6_to_lan4(claimed).is_none(), "{claimed}");
        }
        // The exact lookups are unchanged.
        assert!(table.by_eam4(v4("10.9.1.2")).is_some());
        assert!(table.by_peer6_eam4(v4("10.9.1.255")).is_some());
        for addr in ["10.9.1.0", "10.9.1.3", "10.9.1.254"] {
            let addr = v4(addr);
            let (addr6, owner) = table.lan4_to_lan6(addr).unwrap();
            assert_eq!(owner, Some(peer(3)));
            assert_eq!(table.lan6_to_lan4(addr6), Some((addr, owner)));
        }
        // Up to 10.9.1.0, 10.9.1.3 to 10.9.1.254 and, for the /0, from
        // 10.9.2.0 on.
        let expected = if len4 == 0 { 3 } else { 2 };
        assert_eq!(table.lans.len(), expected, "/{len4}");
    }
}

#[test]
fn the_same_prefix_twice_is_rejected() {
    for (prefix, len4) in [("10.0.0.0", 24), ("0.0.0.0", 0), ("10.0.0.7", 32)] {
        let builder = nested()
            .lan(lan(prefix, len4, "fd64:1::", None))
            .lan(lan("10.0.0.0", 8, "fd64:3::", None))
            .lan(lan(prefix, len4, "fd64:2::", Some(1)));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4(prefix), len4));
    }
    // The same network with another length nests.
    let table = nested()
        .lan(lan("10.0.0.0", 24, "fd64:1::", None))
        .lan(lan("10.0.0.0", 8, "fd64:2::", Some(1)))
        .build()
        .unwrap();
    assert_eq!(
        table.lan4_to_lan6(v4("10.0.0.5")),
        Some((v6("fd64:1::a00:5"), None))
    );
    assert_eq!(
        table.lan4_to_lan6(v4("10.0.1.5")),
        Some((v6("fd64:2::a00:105"), Some(peer(1))))
    );
    assert_eq!(owners(&table), [(v4("10.0.0.0"), 24), (v4("10.0.0.0"), 8)]);
}

#[test]
fn a_shadowed_prefix_owns_no_segment() {
    let table = nested()
        .lan(lan("10.0.0.0", 23, "fd64:1::", None))
        .lan(lan("10.0.1.0", 24, "fd64:2::", Some(1)))
        .lan(lan("10.0.0.0", 24, "fd64:3::", Some(2)))
        .build()
        .unwrap();
    assert_eq!(owners(&table), [(v4("10.0.0.0"), 24), (v4("10.0.1.0"), 24)]);
    for addr in ["10.0.0.0", "10.0.0.255", "10.0.1.0", "10.0.1.255"] {
        let addr = v4(addr);
        let claimed = Ipv6Addr::from_bits(v6("fd64:1::").to_bits() | u128::from(addr.to_bits()));
        assert!(table.lan6_to_lan4(claimed).is_none(), "{addr}");
        assert_ne!(table.lan4_to_lan6(addr).unwrap().1, None, "{addr}");
    }
}

#[test]
fn a_31_with_both_addresses_exact_is_accepted() {
    let table = nested()
        .self_mapping(own("10.9.1.4"))
        .peer(PeerId::new(1), mapping(1, Some(v4("10.9.1.5"))))
        .lan(lan("10.9.1.4", 31, "fd64:1::", None))
        .build()
        .unwrap();
    assert_eq!(owners(&table), Vec::new());
    for addr in ["10.9.1.4", "10.9.1.5"] {
        assert!(table.lan4_to_lan6(v4(addr)).is_none());
    }
    assert!(table.lan6_to_lan4(v6("fd64:1::a09:104")).is_none());
}

#[test]
fn a_32_equal_to_an_exact_address_is_rejected() {
    let builder = nested()
        .self_mapping(own("10.9.1.1"))
        .peer(PeerId::new(1), mapping(1, Some(v4("10.9.1.2"))))
        .peer_with_peer6_eam4(PeerId::new(2), mapping(2, None), v4("10.9.1.3"))
        .lan(lan("10.0.0.0", 8, "fd64:8::", Some(3)));
    for exact in ["10.9.1.1", "10.9.1.2", "10.9.1.3"] {
        let builder = builder.clone().lan(lan(exact, 32, "fd64:1::", None));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4(exact), 32));
    }
    // Next to them is fine.
    let builder = builder.lan(lan("10.9.1.4", 32, "fd64:1::", None));
    assert!(builder.build().is_ok());
}

#[test]
fn prefix_mapping_lans_nest() {
    let table = nested()
        .lan(LanPrefix {
            lan6: (v6("fd64:c::c0a8:0"), 112),
            ..lan("10.9.0.0", 16, "::", Some(1))
        })
        .lan(LanPrefix {
            lan6: (v6("fd64:d::ac10:100"), 120),
            ..lan("10.9.1.0", 24, "::", Some(2))
        })
        .build()
        .unwrap();
    let vectors = [
        ("10.9.1.5", "fd64:d::ac10:105", Some(peer(2))),
        ("10.9.2.5", "fd64:c::c0a8:205", Some(peer(1))),
        ("10.9.0.255", "fd64:c::c0a8:ff", Some(peer(1))),
    ];
    for (addr4, addr6, owner) in vectors {
        assert_eq!(table.lan4_to_lan6(v4(addr4)), Some((v6(addr6), owner)));
        assert_eq!(table.lan6_to_lan4(v6(addr6)), Some((v4(addr4), owner)));
    }
    // 10.9.1.5 claimed under the /16's base.
    assert!(table.lan6_to_lan4(v6("fd64:c::c0a8:105")).is_none());
}

#[test]
fn lan6_rules_are_unchanged() {
    // Two prefixes in one base, a shadowed one included.
    let builder = nested()
        .lan(lan("10.0.0.0", 8, "fd64:1::", None))
        .lan(lan("10.0.0.0", 9, "fd64:2::", None))
        .lan(lan("10.128.0.0", 9, "fd64:3::", None))
        .lan(lan("192.168.0.0", 16, "fd64:1::", None));
    assert_eq!(err(builder), TableError::Lan6Overlap(v6("fd64:1::")));
    let one = mapping(1, None);
    for addr in [
        one.peer6,
        one.eam6,
        one.local6.unwrap(),
        own("10.0.0.1").eam6,
    ] {
        let base = Ipv6Addr::from_bits(addr.to_bits() & !LAN6_HOST_MASK);
        let builder = nested()
            .self_mapping(own("10.0.0.1"))
            .peer(PeerId::new(1), one)
            .lan(lan("0.0.0.0", 0, "fd64:1::", None))
            .lan(LanPrefix {
                lan6: (base, LAN6_PREFIX_LEN),
                ..lan("10.0.0.0", 8, "::", None)
            });
        assert_eq!(err(builder), TableError::Lan6Overlap(base), "{addr}");
    }
    // Shape errors stay, in input order.
    let builder = nested()
        .lan(lan("10.0.0.0", 8, "fd64:1::", None))
        .lan(lan("10.0.0.1", 24, "fd64:2::", None))
        .lan(lan("10.0.0.0", 8, "fd64:3::1", None));
    assert_eq!(err(builder), TableError::InvalidLan4(v4("10.0.0.1"), 24));
}

/// Whether the prefix under the /96 base `base` is simple.
fn simple(table: &TranslationTable, base: &str) -> bool {
    table.by_lan6[&v6(base).to_bits()].simple
}

#[test]
fn a_simple_prefix_next_to_a_whole_space_maps_back() {
    let table = nested()
        .lan(lan("0.0.0.0", 0, "fd64:1::", Some(1)))
        .lan(lan("10.1.0.0", 16, "fd64:2::", Some(2)))
        .build()
        .unwrap();
    assert!(simple(&table, "fd64:2::"));
    assert!(!simple(&table, "fd64:1::"));
    let cases = [
        ("fd64:2::a01:5", Some(("10.1.0.5", 2))),
        ("fd64:2::a01:ffff", Some(("10.1.255.255", 2))),
        ("fd64:2::a02:5", None),
        ("fd64:2::a00:ffff", None),
        ("fd64:1::a01:5", None),
        ("fd64:1::a02:5", Some(("10.2.0.5", 1))),
        ("fd64:1::a00:ffff", Some(("10.0.255.255", 1))),
    ];
    for (addr6, expected) in cases {
        let expected = expected.map(|(addr4, n)| (v4(addr4), Some(peer(n))));
        assert_eq!(table.lan6_to_lan4(v6(addr6)), expected, "{addr6}");
    }
}

#[test]
fn a_prefix_with_a_hole_or_an_inner_prefix_is_not_simple() {
    let table = nested()
        .peer(PeerId::new(1), mapping(1, Some(v4("10.0.0.7"))))
        .lan(lan("10.0.0.0", 24, "fd64:1::", None))
        .lan(lan("10.0.0.6", 31, "fd64:2::", None))
        .lan(lan("172.16.0.0", 16, "fd64:3::", None))
        .lan(lan("172.16.1.0", 24, "fd64:4::", Some(1)))
        .lan(lan("172.16.0.0", 24, "fd64:5::", Some(1)))
        .lan(lan("192.168.0.0", 24, "fd64:6::", None))
        .build()
        .unwrap();
    // A hole, an inner prefix, a prefix with a hole, inner ones, none.
    for (base, expected) in [
        ("fd64:1::", false),
        ("fd64:2::", false),
        ("fd64:3::", false),
        ("fd64:4::", true),
        ("fd64:5::", true),
        ("fd64:6::", true),
    ] {
        assert_eq!(simple(&table, base), expected, "{base}");
    }
    // Shadowed entirely.
    let table = nested()
        .lan(lan("10.0.0.0", 23, "fd64:1::", None))
        .lan(lan("10.0.0.0", 24, "fd64:2::", None))
        .lan(lan("10.0.1.0", 24, "fd64:3::", None))
        .build()
        .unwrap();
    assert!(!simple(&table, "fd64:1::"));
    assert!(simple(&table, "fd64:2::") && simple(&table, "fd64:3::"));
    // Strict prefixes are all simple.
    let table = TranslationTable::builder()
        .lan(lan("10.0.0.0", 24, "fd64:1::", None))
        .build()
        .unwrap();
    assert!(simple(&table, "fd64:1::"));
}

/// The bench's `table_build/nested_10k` model: a /0, 9 /8s, 90 /16s and
/// 9900 /24s, with 10 000 peer `eam4`s inside them.
#[test]
fn segment_count_at_10k_prefixes_and_10k_exact_addresses() {
    let mut builder = nested().lan(LanPrefix {
        lan4: (Ipv4Addr::UNSPECIFIED, 0),
        lan6: (Ipv6Addr::new(0xfd65, 0, 0, 0, 0, 0, 0, 0), 96),
        peer: Some(peer(1)),
    });
    let mut n = 0_u16;
    let mut add = |builder: TranslationTableBuilder, lan4: Ipv4Addr, len4: u8| {
        n += 1;
        builder.lan(LanPrefix {
            lan4: (lan4, len4),
            lan6: (Ipv6Addr::new(0xfd64, 0, 0, 0, 0, n, 0, 0), 96),
            peer: Some(PeerId::new(u32::from(n % 100 + 1))),
        })
    };
    for a in 1..=9_u8 {
        builder = add(builder, Ipv4Addr::new(a, 0, 0, 0), 8);
        for b in 0..10 {
            builder = add(builder, Ipv4Addr::new(a, b, 0, 0), 16);
        }
        for b in 0..=10 {
            for c in 0..100 {
                builder = add(builder, Ipv4Addr::new(a, b, c, 0), 24);
            }
        }
    }
    assert_eq!(n, 9999);
    for n in 1..=10_000_u16 {
        let i = u32::from(n);
        let eam4 = Ipv4Addr::new(
            u8::try_from(1 + i % 9).unwrap(),
            u8::try_from(i / 9 % 11).unwrap(),
            u8::try_from(i / 99).unwrap(),
            200,
        );
        builder = builder.peer(
            PeerId::new(i),
            PeerMapping {
                local6: None,
                ..mapping(n, Some(eam4))
            },
        );
    }
    let table = builder.build().unwrap();
    let (prefixes, exact) = (10_000, 10_000);
    println!(
        "nested segments: {} for {prefixes} prefixes and {exact} exact addresses",
        table.lans.len()
    );
    assert!(table.lans.len() <= 2 * (prefixes + exact) + 1);
}

// --- Randomized comparison with a naive reference ---

/// A std-only xorshift64 generator with a fixed seed.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn u32_below(&mut self, n: u64) -> u32 {
        u32::try_from(self.below(n)).unwrap()
    }
}

/// A random table model: the LAN prefixes and the exact addresses.
#[derive(Debug, Clone)]
struct Model {
    lans: Vec<LanPrefix>,
    self_eam4: Option<u32>,
    /// Per peer (1-based): its `eam4` and `peer6_eam4`.
    peers: Vec<(Option<u32>, Option<u32>)>,
}

/// An address in a small space, so prefixes nest and collide often.
fn random_addr(rng: &mut Xorshift) -> u32 {
    0x0a00_0000 | (rng.u32_below(4) << 16) | (rng.u32_below(4) << 8) | rng.u32_below(8)
}

fn host_mask(len4: u8) -> u32 {
    u32::MAX.checked_shr(u32::from(len4)).unwrap_or(0)
}

fn random_model(rng: &mut Xorshift) -> Model {
    const LENGTHS: [u8; 12] = [0, 8, 12, 14, 16, 20, 22, 24, 29, 30, 31, 32];
    let allow_repeat = rng.below(16) == 0;
    let mut lans: Vec<LanPrefix> = Vec::new();
    for index in 0..rng.below(13) {
        let len4 = LENGTHS[usize::try_from(rng.below(12)).unwrap()];
        let start = random_addr(rng) & !host_mask(len4);
        let lan4 = (Ipv4Addr::from_bits(start), len4);
        if !allow_repeat && lans.iter().any(|lan| lan.lan4 == lan4) {
            continue;
        }
        let base = (0xfd64_u128 << 112) | (u128::from(index + 1) << 64);
        let lan6 = if len4 > 0 && rng.below(3) == 0 {
            let embedded = u32::try_from(rng.next() >> 32).unwrap() & !host_mask(len4);
            (Ipv6Addr::from_bits(base | u128::from(embedded)), 96 + len4)
        } else {
            (Ipv6Addr::from_bits(base), 96)
        };
        let owner = rng.below(4);
        lans.push(LanPrefix {
            lan4,
            lan6,
            peer: (owner > 0).then(|| PeerId::new(u32::try_from(owner).unwrap())),
        });
    }
    let mut used = HashSet::new();
    let mut exact = |rng: &mut Xorshift| {
        let addr = random_addr(rng);
        (rng.below(2) == 0 && used.insert(addr)).then_some(addr)
    };
    let self_eam4 = exact(rng);
    let peers = (0..4).map(|_| (exact(rng), exact(rng))).collect();
    Model {
        lans,
        self_eam4,
        peers,
    }
}

impl Model {
    fn builder(&self) -> TranslationTableBuilder {
        let mut builder = TranslationTable::builder();
        if let Some(addr) = self.self_eam4 {
            builder = builder.self_mapping(SelfMapping {
                eam4: Ipv4Addr::from_bits(addr),
                eam6: v6("fd00::ff:1"),
            });
        }
        for (n, (eam4, peer6_eam4)) in (1..).zip(&self.peers) {
            let mapping = PeerMapping {
                local6: None,
                ..mapping(n, eam4.map(Ipv4Addr::from_bits))
            };
            let id = PeerId::new(u32::from(n));
            builder = match peer6_eam4 {
                Some(addr) => builder.peer_with_peer6_eam4(id, mapping, Ipv4Addr::from_bits(*addr)),
                None => builder.peer(id, mapping),
            };
        }
        self.lans
            .iter()
            .fold(builder, |builder, lan| builder.lan(*lan))
    }

    fn exact(&self) -> Vec<u32> {
        self.peers
            .iter()
            .flat_map(|(eam4, peer6_eam4)| [*eam4, *peer6_eam4])
            .chain([self.self_eam4])
            .flatten()
            .collect()
    }

    /// The prefixes, with the model's exact addresses, that a strict table
    /// accepts: each one disjoint from the earlier ones and from every
    /// exact address.
    fn disjoint(&self) -> Self {
        let exact = self.exact();
        let mut lans: Vec<LanPrefix> = Vec::new();
        for lan in &self.lans {
            if !exact.iter().any(|&addr| contains(lan, addr))
                && !lans.iter().any(|kept| overlap(kept, lan))
            {
                lans.push(*lan);
            }
        }
        Self {
            lans,
            ..self.clone()
        }
    }
}

fn bounds(lan: &LanPrefix) -> (u32, u32) {
    let start = lan.lan4.0.to_bits();
    (start, start | host_mask(lan.lan4.1))
}

fn contains(lan: &LanPrefix, addr: u32) -> bool {
    let (start, end) = bounds(lan);
    start <= addr && addr <= end
}

fn overlap(a: &LanPrefix, b: &LanPrefix) -> bool {
    let ((a0, a1), (b0, b1)) = (bounds(a), bounds(b));
    a0 <= b1 && b0 <= a1
}

/// The naive longest match: `None` for an exact address.
fn longest(model: &Model, addr: u32) -> Option<&LanPrefix> {
    if model.exact().contains(&addr) {
        return None;
    }
    model
        .lans
        .iter()
        .filter(|lan| contains(lan, addr))
        .max_by_key(|lan| lan.lan4.1)
}

/// The low 32 bits of `lan`'s IPv6 address for `addr` (inside `lan4`).
fn embed(lan: &LanPrefix, addr: u32) -> u32 {
    if lan.lan6.1 == 96 {
        addr
    } else {
        let embedded = u32::try_from(lan.lan6.0.to_bits() & 0xFFFF_FFFF).unwrap();
        embedded | (addr & host_mask(lan.lan4.1))
    }
}

fn ref_lan4_to_lan6(model: &Model, addr: u32) -> Option<(Ipv6Addr, Option<PeerId>)> {
    let lan = longest(model, addr)?;
    let base = lan.lan6.0.to_bits() & !0xFFFF_FFFF;
    Some((
        Ipv6Addr::from_bits(base | u128::from(embed(lan, addr))),
        lan.peer,
    ))
}

fn ref_lan6_to_lan4(model: &Model, addr: Ipv6Addr) -> Option<(Ipv4Addr, Option<PeerId>)> {
    let bits = addr.to_bits();
    let lan = model
        .lans
        .iter()
        .find(|lan| lan.lan6.0.to_bits() & !0xFFFF_FFFF == bits & !0xFFFF_FFFF)?;
    let low = u32::try_from(bits & 0xFFFF_FFFF).unwrap();
    let host = host_mask(lan.lan4.1);
    let addr4 = if lan.lan6.1 == 96 {
        low
    } else if low & !host == embed(lan, 0) {
        lan.lan4.0.to_bits() | (low & host)
    } else {
        return None;
    };
    (contains(lan, addr4) && longest(model, addr4) == Some(lan))
        .then_some((Ipv4Addr::from_bits(addr4), lan.peer))
}

/// The error a nested table gives for `model`, if any.
fn ref_nested_error(model: &Model) -> Option<TableError> {
    let repeated = model
        .lans
        .iter()
        .enumerate()
        .filter(|&(i, lan)| model.lans[..i].iter().any(|other| other.lan4 == lan.lan4))
        .map(|(_, lan)| (lan.lan4.0.to_bits(), lan.lan4.1))
        .min();
    let exact32 = || {
        model
            .lans
            .iter()
            .filter(|lan| lan.lan4.1 == 32 && model.exact().contains(&lan.lan4.0.to_bits()))
            .map(|lan| lan.lan4.0.to_bits())
            .min()
            .map(|addr| (addr, 32))
    };
    repeated
        .or_else(exact32)
        .map(|(addr, len)| TableError::Lan4Overlap(Ipv4Addr::from_bits(addr), len))
}

/// The prefixes a strict (0.14.2) table may report: one that overlaps
/// another prefix, else one that contains an exact address.
fn ref_strict_errors(model: &Model) -> Vec<TableError> {
    let report = |lan: &LanPrefix| TableError::Lan4Overlap(lan.lan4.0, lan.lan4.1);
    let overlapping: Vec<_> = model
        .lans
        .iter()
        .enumerate()
        .filter(|&(i, lan)| {
            model
                .lans
                .iter()
                .enumerate()
                .any(|(j, other)| i != j && overlap(lan, other))
        })
        .map(|(_, lan)| report(lan))
        .collect();
    if !overlapping.is_empty() {
        return overlapping;
    }
    let exact = model.exact();
    model
        .lans
        .iter()
        .filter(|lan| exact.iter().any(|&addr| contains(lan, addr)))
        .map(report)
        .collect()
}

/// The IPv4 addresses to look up: the prefix bounds and middles, the exact
/// addresses and their neighbours, the space ends and random ones.
fn probes(model: &Model, rng: &mut Xorshift) -> Vec<u32> {
    let mut probes = vec![0, u32::MAX];
    for lan in &model.lans {
        let (start, end) = bounds(lan);
        probes.extend([start, end, start.saturating_add(1), end.saturating_sub(1)]);
        probes.extend([
            start + (end - start) / 2,
            start.wrapping_sub(1),
            end.wrapping_add(1),
        ]);
    }
    for addr in model.exact() {
        probes.extend([addr, addr.wrapping_sub(1), addr.wrapping_add(1)]);
    }
    probes.extend((0..32).map(|_| random_addr(rng)));
    probes
}

/// Compares `table` with the reference for every probe, both ways.
fn check_lookups(table: &TranslationTable, model: &Model, rng: &mut Xorshift, seed: u64) {
    let probes = probes(model, rng);
    for &addr in &probes {
        let expected = ref_lan4_to_lan6(model, addr);
        let addr4 = Ipv4Addr::from_bits(addr);
        assert_eq!(table.lan4_to_lan6(addr4), expected, "seed {seed}: {addr4}");
        if let Some((addr6, owner)) = expected {
            assert_eq!(
                table.lan6_to_lan4(addr6),
                Some((addr4, owner)),
                "seed {seed}"
            );
        }
    }
    for lan in &model.lans {
        let base = lan.lan6.0.to_bits() & !0xFFFF_FFFF;
        for &addr in &probes {
            for low in [addr, embed(lan, addr)] {
                let addr6 = Ipv6Addr::from_bits(base | u128::from(low));
                assert_eq!(
                    table.lan6_to_lan4(addr6),
                    ref_lan6_to_lan4(model, addr6),
                    "seed {seed}: {addr6}"
                );
            }
        }
    }
}

fn check_nested(model: &Model, rng: &mut Xorshift, seed: u64) {
    let built = model.builder().nested_lans().build();
    if let Some(error) = ref_nested_error(model) {
        assert_eq!(built.unwrap_err(), error, "seed {seed}: {model:?}");
    } else {
        let table = built.unwrap();
        let bound = 2 * (model.lans.len() + model.exact().len()) + 1;
        assert!(table.lans.len() <= bound, "seed {seed}");
        check_lookups(&table, model, rng, seed);
    }
}

fn check_strict(model: &Model, rng: &mut Xorshift, seed: u64) {
    let built = model.builder().build();
    let errors = ref_strict_errors(model);
    if errors.is_empty() {
        let table = built.unwrap();
        assert_eq!(table.lans.len(), model.lans.len(), "seed {seed}");
        check_lookups(&table, model, rng, seed);
    } else {
        let error = built.unwrap_err();
        assert!(
            errors.contains(&error),
            "seed {seed}: {error:?} not in {errors:?}"
        );
    }
}

#[test]
fn random_tables_match_the_naive_reference_in_both_modes() {
    for seed in 1..=600_u64 {
        let mut rng = Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let model = random_model(&mut rng);
        check_nested(&model, &mut rng, seed);
        check_strict(&model, &mut rng, seed);
        // A disjoint model: both modes accept it and agree.
        let disjoint = model.disjoint();
        check_nested(&disjoint, &mut rng, seed);
        check_strict(&disjoint, &mut rng, seed);
        let (strict, nested) = (
            disjoint.builder().build().unwrap(),
            disjoint.builder().nested_lans().build().unwrap(),
        );
        assert_eq!(strict.lans, nested.lans, "seed {seed}");
    }
}
