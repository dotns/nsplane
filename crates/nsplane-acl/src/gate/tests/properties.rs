//! Property tests of the gate on untrusted packets: the header parsers against the header
//! layouts, and the decisions of two gates in the same state.
//!
//! The cases come from a seeded generator, so every run tests the same inputs.

use std::sync::Mutex;

use super::super::packet::{PacketMeta, parse_v6};
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

const OTHER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
const OTHER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9);

fn mutate(rng: &mut Rng, packet: &mut Vec<u8>) {
    for _ in 0..=rng.below(2) {
        match rng.below(6) {
            // The headers decide: most changes land there.
            0 | 1 if !packet.is_empty() => {
                let at = rng.below(packet.len().min(64));
                packet[at] ^= 1 << rng.below(8);
            }
            2 if !packet.is_empty() => {
                let at = rng.below(packet.len().min(64));
                packet[at] = rng.pick(&[0, 1, 6, 17, 43, 44, 58, 60, 255]);
            }
            3 => packet.truncate(rng.below(packet.len() + 1)),
            4 => {
                let tail: Vec<u8> = (0..=rng.below(11)).map(|_| rng.byte()).collect();
                packet.extend_from_slice(&tail);
            }
            // A length field.
            _ if packet.len() >= 6 => {
                let at = if packet[0] >> 4 == 6 { 5 } else { 3 };
                packet[at] = packet[at].wrapping_add(rng.pick(&[1, 8, 20, 0xff, 0xf8]));
            }
            _ => {}
        }
    }
}

/// The upper-layer header of a packet of `protocol` (`icmp` for the family).
fn upper(rng: &mut Rng, protocol: u8, icmp: u8, ports: (u16, u16)) -> Vec<u8> {
    match protocol {
        6 => tcp_header(
            ports.0,
            ports.1,
            rng.pick(&[0x02, 0x02, 0x10, 0x12, 0x11, 0x04]),
        )
        .to_vec(),
        17 => udp_header(ports.0, ports.1).to_vec(),
        _ if protocol == icmp => {
            let kind = if icmp == 1 {
                rng.pick(&[8, 0, 3, 11, 13])
            } else {
                rng.pick(&[128, 129, 1, 3, 135])
            };
            let mut header = icmp_header(kind, ports.0).to_vec();
            if rng.chance(10) {
                header[1] = 1;
            }
            header
        }
        _ => (0..rng.below(12)).map(|_| rng.byte()).collect(),
    }
}

/// A packet between `src` and `dst`, whole or a fragment, with IPv4 options in some.
fn packet4(rng: &mut Rng, src: Ipv4Addr, dst: Ipv4Addr, ports: (u16, u16)) -> Vec<u8> {
    let protocol = rng.pick(&[6, 6, 17, 17, 1, 1, 47]);
    let mut packet = ipv4(src, dst, protocol, &upper(rng, protocol, 1, ports));
    if rng.chance(10) {
        // Four bytes of options.
        packet[0] = 0x46;
        packet.splice(20..20, [1, 1, 1, 1]);
        let total = u16::try_from(packet.len()).unwrap();
        packet[2..4].copy_from_slice(&total.to_be_bytes());
    }
    let id = rng.pick(&[1, 2, 3]);
    match rng.below(10) {
        0 => fragment(packet, id, 0, true),
        1 => fragment(packet, id, rng.pick(&[1, 2, 185]), rng.chance(50)),
        _ => packet,
    }
}

/// A packet between `src` and `dst` behind up to nine extension headers.
fn packet6(rng: &mut Rng, src: Ipv6Addr, dst: Ipv6Addr, ports: (u16, u16)) -> Vec<u8> {
    let protocol = rng.pick(&[6, 6, 17, 17, 58, 58, 47]);
    let count = if rng.chance(60) {
        0
    } else {
        rng.pick(&[1, 1, 2, 3, 8, 9])
    };
    let mut extensions: Vec<Extension> = (0..count)
        .map(|_| match rng.below(5) {
            0 => ah(),
            kind => options([0, 43, 60, 60][kind - 1], rng.pick(&[1, 1, 2])),
        })
        .collect();
    if rng.chance(20) {
        let offset = if rng.chance(50) {
            0
        } else {
            rng.pick(&[1, 2, 185])
        };
        let at = rng.below(extensions.len() + 1);
        extensions.insert(at, fragment6(rng.pick(&[1, 2, 3]), offset, rng.chance(50)));
        if rng.chance(10) {
            extensions.push(fragment6(4, 0, false));
        }
    }
    ipv6_with(
        src,
        dst,
        &extensions,
        protocol,
        &upper(rng, protocol, 58, ports),
    )
}

const fn read16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// What a header says about its packet: protocol, ports, TCP flags, ICMP type and
/// identifier, and the fragment identification, offset and more-fragments flag.
#[derive(Debug, PartialEq, Eq)]
struct Fields {
    protocol: u8,
    ports: Option<(u16, u16)>,
    tcp_flags: u8,
    icmp: Option<(u8, u16)>,
    fragment: (u32, u16, bool),
}

impl Fields {
    /// The fields of the upper layer `payload`, `None` when its header is cut off or an
    /// echo message carries a code.
    fn upper(
        protocol: u8,
        icmp: u8,
        echo: [u8; 2],
        payload: &[u8],
        fragment: (u32, u16, bool),
    ) -> Option<Self> {
        let mut fields = Self {
            protocol,
            ports: None,
            tcp_flags: 0,
            icmp: None,
            fragment,
        };
        if fragment.1 != 0 {
            // A later fragment holds no upper-layer header.
            return Some(fields);
        }
        match protocol {
            6 => {
                fields.ports = Some((read16(payload.get(..20)?, 0), read16(payload, 2)));
                fields.tcp_flags = payload[13];
            }
            17 => fields.ports = Some((read16(payload.get(..8)?, 0), read16(payload, 2))),
            _ if protocol == icmp => {
                let header = payload.get(..8)?;
                if echo.contains(&header[0]) && header[1] != 0 {
                    return None;
                }
                fields.icmp = Some((header[0], read16(header, 4)));
            }
            _ => {}
        }
        Some(fields)
    }

    fn of<A: GateAddr>(meta: &PacketMeta<A>, fragment_id: u32) -> Self {
        Self {
            protocol: meta.protocol,
            ports: meta.src_port.zip(meta.dst_port),
            tcp_flags: meta.tcp_flags,
            icmp: meta.icmp_type.zip(meta.icmp_identifier),
            fragment: (fragment_id, meta.fragment_offset, meta.more_fragments),
        }
    }
}

/// RFC 791: the fields of an IPv4 packet, `None` when its lengths do not hold.
fn expected_v4(packet: &[u8]) -> Option<Fields> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(read16(packet, 2));
    if header < 20 || total < header || packet.len() < total {
        return None;
    }
    let flags = read16(packet, 6);
    let fragment = (
        u32::from(read16(packet, 4)),
        flags & 0x1fff,
        flags & 0x2000 != 0,
    );
    Fields::upper(packet[9], 1, [0, 8], &packet[header..total], fragment)
}

/// RFC 8200: the fields of an IPv6 packet behind at most eight extension headers, one of
/// them a Fragment header; `None` when a header is cut off or the chain does not end.
fn expected_v6(packet: &[u8]) -> Option<Fields> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let packet = packet.get(..40 + usize::from(read16(packet, 4)))?;
    let (mut next, mut offset, mut headers) = (packet[6], 40, 0);
    let mut fragment = None;
    loop {
        let length = match next {
            0 | 43 | 60 => (usize::from(*packet.get(offset + 1)?) + 1) * 8,
            51 => (usize::from(*packet.get(offset + 1)?) + 2) * 4,
            44 if fragment.is_none() => 8,
            44 => return None,
            _ => break,
        };
        headers += 1;
        let header = packet.get(offset..offset + length)?;
        if headers > 8 {
            return None;
        }
        if next == 44 {
            let field = read16(header, 2);
            let id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            fragment = Some((id, field >> 3, field & 1 != 0));
        }
        next = header[0];
        offset += length;
        if fragment.is_some_and(|(_, units, _)| units != 0) {
            break;
        }
    }
    let fragment = fragment.unwrap_or((0, 0, false));
    Fields::upper(next, 58, [128, 129], &packet[offset..], fragment)
}

#[test]
fn the_parsers_read_what_the_headers_say() {
    let mut rng = Rng(0x5eed_ac01);
    let (mut parsed4, mut refused4, mut parsed6, mut refused6) = (0, 0, 0, 0);
    for _ in 0..40_000 {
        let ports = (rng.pick(&[0, 80, 4000]), rng.pick(&[80, 443, 0]));
        let v6 = rng.chance(50);
        let mut packet = if v6 {
            packet6(&mut rng, REMOTE6, LOCAL6, ports)
        } else {
            packet4(&mut rng, REMOTE, LOCAL, ports)
        };
        if rng.chance(60) {
            mutate(&mut rng, &mut packet);
        }

        let v4 = PacketMeta::<Ipv4Addr>::parse(&packet);
        let expected = expected_v4(&packet);
        assert_eq!(
            v4.map(|meta| Fields::of(&meta, u32::from(meta.identification))),
            expected,
            "{packet:02x?}"
        );
        if let Some(meta) = v4 {
            assert_eq!(meta.source.octets(), packet[12..16]);
            assert_eq!(meta.destination.octets(), packet[16..20]);
            parsed4 += 1;
        } else if !v6 {
            refused4 += 1;
        }

        let v6_meta = parse_v6(&packet);
        let expected = expected_v6(&packet);
        assert_eq!(
            v6_meta.map(|meta| Fields::of(&meta, meta.identification)),
            expected,
            "{packet:02x?}"
        );
        if let Some(meta) = v6_meta {
            assert_eq!(meta.source.octets(), packet[8..24]);
            assert_eq!(meta.destination.octets(), packet[24..40]);
            parsed6 += 1;
        } else if v6 {
            refused6 += 1;
        }
    }
    assert!(
        parsed4 > 10_000 && refused4 > 2_000 && parsed6 > 10_000 && refused6 > 2_000,
        "{parsed4} {refused4} {parsed6} {refused6}"
    );
}

/// Grants for `remote` of every protocol, to the local address inbound and to the remote
/// one outbound, in both families.
fn untrusted_policy(mode6: GateMode) -> GatePolicy {
    policy(vec![
        scope(
            "v4",
            GateMode::Enforce,
            vec![inbound_any("in", "remote"), outbound_any("out", "remote")],
        ),
        scope6(
            "v6",
            mode6,
            vec![
                grant(
                    "in6",
                    Direction::Inbound,
                    &["remote"],
                    vec![host6(LOCAL6)],
                    vec![ProtocolMatch::Any],
                ),
                grant(
                    "out6",
                    Direction::Outbound,
                    &["remote"],
                    vec![host6(REMOTE6)],
                    vec![ProtocolMatch::Any],
                ),
            ],
        ),
    ])
}

/// A gate with small limits, so that the capacity paths are taken, on `clock`.
fn small_gate(clock: &Arc<Mutex<Instant>>, mode6: GateMode) -> Arc<FlowGate> {
    let clock = Arc::clone(clock);
    let gate = FlowGate::with_clock(
        GateConfig {
            limits: GateLimits {
                flows: 48,
                flows_per_peer: 40,
                fragments: 8,
            },
            ..GateConfig::default()
        },
        move || *clock.lock().unwrap(),
    );
    gate.replace(untrusted_policy(mode6)).unwrap();
    gate
}

/// A packet for the gate: mostly between the bound addresses in the direction it travels,
/// sometimes an ICMP error about an earlier packet, sometimes changed.
fn gate_packet(rng: &mut Rng, direction: PacketDirection, sent: &[Vec<u8>]) -> Vec<u8> {
    let v6 = rng.chance(40);
    let inbound = direction == PacketDirection::Inbound;
    let ports = (rng.pick(&[4000, 4001, 4002, 0]), rng.pick(&[80, 443, 53]));
    let ports = if inbound { ports } else { (ports.1, ports.0) };
    let stray = rng.chance(10);
    let mut packet = if !sent.is_empty() && rng.chance(12) {
        // An error from the far end of an earlier packet, quoting it.
        let quoted = &sent[rng.below(sent.len())];
        if quoted[0] >> 4 == 6 && quoted.len() >= 40 {
            let (src, dst) = (address_of6(quoted, 24), address_of6(quoted, 8));
            icmp6_error(src, dst, rng.pick(&[1, 3]), quoted)
        } else if quoted.len() >= 20 {
            let src = Ipv4Addr::new(quoted[16], quoted[17], quoted[18], quoted[19]);
            let dst = Ipv4Addr::new(quoted[12], quoted[13], quoted[14], quoted[15]);
            icmp_error(src, dst, quoted)
        } else {
            quoted.clone()
        }
    } else if v6 {
        let remote = if stray { OTHER6 } else { REMOTE6 };
        let (src, dst) = if inbound {
            (remote, LOCAL6)
        } else {
            (LOCAL6, remote)
        };
        packet6(rng, src, dst, ports)
    } else {
        let remote = if stray { OTHER } else { REMOTE };
        let (src, dst) = if inbound {
            (remote, LOCAL)
        } else {
            (LOCAL, remote)
        };
        packet4(rng, src, dst, ports)
    };
    if rng.chance(30) {
        mutate(rng, &mut packet);
    }
    packet
}

fn address_of6(packet: &[u8], at: usize) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[at..at + 16]).unwrap())
}

/// The flow and fragment entries the gate counts.
fn entries(gate: &FlowGate) -> (usize, usize) {
    let counts = &gate.state.counts;
    (
        counts.flows.load(Ordering::SeqCst),
        counts.fragments.load(Ordering::SeqCst),
    )
}

const fn allowed(decision: &GateDecision) -> bool {
    matches!(
        decision,
        GateDecision::Enforce { allow: true, .. } | GateDecision::Observe { allow: true, .. }
    )
}

#[test]
fn two_gates_in_the_same_state_decide_untrusted_packets_alike() {
    let mut rng = Rng(0x5eed_ac02);
    let mut seen = [0_u32; 5];
    for round in 0..60 {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let mode6 = if round % 2 == 0 {
            GateMode::Enforce
        } else {
            GateMode::Observe
        };
        let (gate, twin) = (small_gate(&clock, mode6), small_gate(&clock, mode6));
        let mut sent: Vec<Vec<u8>> = Vec::new();
        for step in 0..1000 {
            let direction = rng.pick(&[PacketDirection::Inbound, PacketDirection::Outbound]);
            let peer = rng.pick(&[PEER, PEER, PEER, OTHER_PEER]);
            let packet = gate_packet(&mut rng, direction, &sent);
            if rng.chance(5) {
                *clock.lock().unwrap() += Duration::from_secs(rng.pick(&[1, 30, 200, 4000]));
            }

            let before = entries(&gate);
            let decision = gate.evaluate(direction, peer, &packet);
            assert_eq!(
                decision,
                twin.evaluate(direction, peer, &packet),
                "{packet:02x?}"
            );
            let after = entries(&gate);
            if step % 50 == 0 {
                assert_eq!(audit_families(&gate), after);
            }

            let version = packet.first().map(|byte| byte >> 4);
            let readable = match version {
                Some(4) => expected_v4(&packet).is_some(),
                Some(6) => expected_v6(&packet).is_some(),
                // Not an IP packet: not the gate's to decide.
                _ => {
                    assert_eq!(decision, GateDecision::Pass);
                    continue;
                }
            };
            // A packet that does not parse is never allowed by a decision, and only an
            // allowed packet adds state.
            assert!(
                readable || !allowed(&decision),
                "{packet:02x?}: {decision:?}"
            );
            if !allowed(&decision) {
                assert!(after.0 <= before.0 && after.1 <= before.1, "{packet:02x?}");
            }
            assert!(after.0 <= before.0 + 1 && after.1 <= before.1 + 1);
            match &decision {
                GateDecision::Enforce { reason, rule, .. }
                | GateDecision::Observe { reason, rule, .. } => {
                    assert_eq!(
                        rule.is_some(),
                        *reason == GateReason::Granted,
                        "{decision:?}"
                    );
                    seen[match reason {
                        GateReason::Granted => 0,
                        GateReason::ValidState => 1,
                        GateReason::Malformed => 2,
                        _ => 3,
                    }] += 1;
                }
                GateDecision::Pass => seen[4] += 1,
            }
            if readable && sent.len() < 32 {
                sent.push(packet);
            } else if readable && step % 4 == 0 {
                let at = rng.below(sent.len());
                sent[at] = packet;
            }
        }
        assert_eq!(gate.counters(), twin.counters());
        assert_eq!(audit_families(&gate), audit_families(&twin));
    }
    assert!(seen.iter().all(|&count| count > 300), "{seen:?}");
}
