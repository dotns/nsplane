//! Property tests of the filter on untrusted packets: two filters in the same state give the
//! same verdict, and every packet is counted once under the outcome its verdict names.
//!
//! The cases come from a seeded generator, so every run tests the same inputs.

use nsplane_packet::IpPacket;

use crate::test_packets::udp;

use super::*;

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    const fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// A packet between the addresses of [`test_policy`], whole or a fragment, sometimes with
/// a few bytes changed.
fn untrusted(rng: &mut Rng, inbound: bool) -> Vec<u8> {
    let v6 = rng.chance(30);
    let (remote, local) = if v6 {
        (rng.pick(&["fd00::1", "fd00::1", "fd00::9"]), "fd00::2")
    } else {
        (rng.pick(&["10.0.0.1", "10.0.0.1", "10.0.0.9"]), "10.0.0.2")
    };
    let (src, dst) = if inbound {
        (addr(remote), addr(local))
    } else {
        (addr(local), addr(remote))
    };
    let ports = (rng.pick(&[4000, 4001]), rng.pick(&[80, 443, 53, 22]));
    let ports = if inbound { ports } else { (ports.1, ports.0) };
    let (proto, transport) = match rng.below(8) {
        0..3 => (protocol::TCP, tcp(ports.0, ports.1, b"data")),
        3 | 4 => (protocol::UDP, udp(ports.0, ports.1, b"data")),
        5 => {
            let (proto, kinds) = if v6 {
                (protocol::ICMPV6, [128, 129, 1])
            } else {
                (protocol::ICMP, [8, 0, 3])
            };
            (proto, icmp_echo(rng.pick(&kinds), 7))
        }
        6 => (rng.pick(&[47, 50]), vec![0; 12]),
        _ => (protocol::TCP, vec![0; rng.below(20)]),
    };
    let frag = (!v6 && rng.chance(25)).then(|| Frag {
        id: rng.pick(&[1, 2, 3]),
        offset_units: rng.pick(&[0, 0, 4]),
        more: rng.chance(60),
    });
    let mut bytes = ip_frag(src, dst, proto, &transport, frag)
        .as_packet()
        .to_vec();
    if rng.chance(30) {
        for _ in 0..=rng.below(2) {
            match rng.below(4) {
                0 | 1 if !bytes.is_empty() => {
                    let at = rng.below(bytes.len().min(48));
                    bytes[at] ^= 1 << rng.below(8);
                }
                2 => bytes.truncate(rng.below(bytes.len() + 1)),
                _ => bytes.push(rng.byte()),
            }
        }
    }
    bytes
}

/// The counters a packet's outcome bumps, in the order of [`REASONS`].
const fn outcomes(stats: &AclFilterStats) -> [u64; 16] {
    [
        stats.accepted,
        stats.replies,
        stats.bypassed,
        stats.ipv6_accepted,
        stats.outbound_replies,
        stats.denied,
        stats.cross_namespace,
        stats.no_policy,
        stats.policy_failed,
        stats.unknown_peer,
        stats.protocol,
        stats.fragment,
        stats.malformed,
        stats.outbound_denied,
        stats.outbound_source,
        stats.internal,
    ]
}

/// The drop reason of each counter of [`outcomes`]; `None` for those of accepted packets.
const REASONS: [Option<&str>; 16] = [
    None,
    None,
    None,
    None,
    None,
    Some(reasons::DENIED),
    Some(reasons::CROSS_NAMESPACE),
    Some(reasons::NO_POLICY),
    Some(reasons::POLICY_FAILED),
    Some(reasons::UNKNOWN_PEER),
    Some(reasons::PROTOCOL),
    Some(reasons::FRAGMENT),
    Some(reasons::MALFORMED),
    Some(reasons::OUTBOUND),
    Some(reasons::OUTBOUND_SOURCE),
    Some(reasons::INTERNAL),
];

/// A filter over an engine of its own with [`test_policy`] and a clock that stands still.
fn untrusted_filter(config: AclFilterConfig) -> AclFilter {
    let (engine, _clock) = clocked_engine(test_policy());
    AclFilter::with_config(engine, identity(), config)
}

#[test]
fn two_filters_in_the_same_state_judge_untrusted_packets_alike_and_count_each_once() {
    let mut rng = Rng(0x5eed_ac11);
    let small = AclFilterConfig {
        fragment_capacity: 4,
        reply_capacity: 4,
        allow_other_protocols: true,
        ..AclFilterConfig::default()
    };
    let configs = [
        AclFilterConfig::default(),
        small,
        allow_only(4),
        stateless_options(Some(Ipv4Addr::new(10, 0, 0, 2))),
    ];
    let mut seen = [0_u32; 16];
    for config in configs {
        let (filter, twin) = (untrusted_filter(config), untrusted_filter(config));
        let whole_packets = config.fragments == FragmentMode::Outcome
            && config.accept_to_local.is_none()
            && !config.accept_icmp_echo_reply;
        for _ in 0..6_000 {
            let is_inbound = rng.chance(60);
            let peer = rng.pick(&[PEER, PEER, OTHER_PEER, KEY_PEER, PeerId::new(99)]);
            let bytes = untrusted(&mut rng, is_inbound);
            let run = |filter: &AclFilter| {
                let packet = PacketBuf::from_packet(&bytes);
                if is_inbound {
                    inbound(filter, peer, packet)
                } else {
                    outbound(filter, peer, packet)
                }
            };
            let before = outcomes(&filter.stats());
            let verdict = run(&filter);
            assert_eq!(verdict, run(&twin), "{bytes:02x?}");
            let after = outcomes(&filter.stats());

            // One counter moves by one, the one of the verdict; an accepted outbound
            // packet that is no reply moves none.
            let moved: Vec<usize> = (0..16).filter(|&i| after[i] != before[i]).collect();
            match (verdict, moved.as_slice()) {
                (Verdict::Accept, []) => assert!(!is_inbound, "{bytes:02x?}"),
                (Verdict::Accept, &[i]) => assert_eq!(REASONS[i], None),
                (Verdict::Drop { reason }, &[i]) => assert_eq!(REASONS[i], Some(reason)),
                other => panic!("{other:?} for {bytes:02x?}"),
            }
            if let &[i] = moved.as_slice() {
                assert_eq!(after[i], before[i] + 1);
                seen[i] += 1;
            }

            let version = bytes.first().map(|byte| byte >> 4);
            if config.ipv6 == Ipv6Mode::Accept && version == Some(6) {
                assert_eq!(verdict, Verdict::Accept);
            } else if whole_packets && is_inbound && IpPacket::parse(&bytes).is_err() {
                // Without the modes that read the raw header, what does not parse is
                // dropped as malformed.
                assert_eq!(verdict, drop(reasons::MALFORMED), "{bytes:02x?}");
            }
        }
        assert_eq!(filter.stats(), twin.stats());
        // The filter's own tables never failed an invariant.
        assert_eq!(filter.stats().internal, 0);
    }
    // Accepted, replies, bypassed, IPv6 accepted, denied, unknown peer, protocol,
    // fragment and malformed all occurred.
    for i in [0, 1, 2, 3, 5, 9, 10, 11, 12] {
        assert!(seen[i] > 50, "{seen:?}");
    }
}
