//! Echo authorization, malformed codes and state correlation.

use super::*;

#[derive(Clone, Copy)]
struct Echo {
    v6: bool,
    request_direction: PacketDirection,
    extensions: bool,
}

impl Echo {
    fn types(self) -> (u8, u8) {
        if self.v6 { (128, 129) } else { (8, 0) }
    }

    fn gate(self) -> Arc<FlowGate> {
        let direction = match self.request_direction {
            PacketDirection::Inbound => Direction::Inbound,
            PacketDirection::Outbound => Direction::Outbound,
        };
        let grants = vec![grant(
            "echo",
            direction,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![self.types().0]))],
        )];
        gate_with(policy(vec![if self.v6 {
            scope6("echo", GateMode::Enforce, grants)
        } else {
            scope("echo", GateMode::Enforce, grants)
        }]))
    }

    fn packet(self, direction: PacketDirection, kind: u8, code: u8, id: u16) -> Vec<u8> {
        let mut header = icmp_header(kind, id);
        header[1] = code;
        if self.v6 {
            let (src, dst) = if direction == PacketDirection::Inbound {
                (REMOTE6, LOCAL6)
            } else {
                (LOCAL6, REMOTE6)
            };
            let extensions = if self.extensions {
                vec![options(0, 1), ah(), options(60, 1)]
            } else {
                vec![]
            };
            ipv6_with(src, dst, &extensions, 58, &header)
        } else {
            let (src, dst) = if direction == PacketDirection::Inbound {
                (REMOTE, LOCAL)
            } else {
                (LOCAL, REMOTE)
            };
            ipv4(src, dst, 1, &header)
        }
    }

    fn reverse(self) -> PacketDirection {
        match self.request_direction {
            PacketDirection::Inbound => PacketDirection::Outbound,
            PacketDirection::Outbound => PacketDirection::Inbound,
        }
    }
}

fn cases() -> impl Iterator<Item = Echo> {
    [false, true].into_iter().flat_map(|v6| {
        [PacketDirection::Inbound, PacketDirection::Outbound]
            .into_iter()
            .flat_map(move |request_direction| {
                [false, true]
                    .into_iter()
                    .filter(move |extensions| v6 || !extensions)
                    .map(move |extensions| Echo {
                        v6,
                        request_direction,
                        extensions,
                    })
            })
    })
}

#[test]
fn echo_code_nonzero_requests_never_create_state() {
    for case in cases() {
        let gate = case.gate();
        for code in 1..=255 {
            let packet = case.packet(case.request_direction, case.types().0, code, 77);
            assert_eq!(
                gate.evaluate(case.request_direction, PEER, &packet),
                denied(GateReason::Malformed)
            );
            assert_eq!(audit_families(&gate), (0, 0));
        }
        assert_eq!(
            gate.evaluate(
                case.reverse(),
                PEER,
                &case.packet(case.reverse(), case.types().1, 0, 77)
            ),
            denied(GateReason::ReverseNewFlow)
        );
        assert_eq!(
            gate.evaluate(
                case.request_direction,
                PEER,
                &case.packet(case.request_direction, case.types().0, 0, 77)
            ),
            granted("echo")
        );
    }
}

#[test]
fn echo_code_existing_state_rejects_nonzero_requests_and_replies_without_refresh() {
    for case in cases() {
        let gate = case.gate();
        let start = Instant::now();
        let request = case.packet(case.request_direction, case.types().0, 0, 77);
        assert_eq!(
            gate.evaluate_at(case.request_direction, PEER, &request, start),
            granted("echo")
        );
        for code in 1..=255 {
            for (direction, kind) in [
                (case.request_direction, case.types().0),
                (case.reverse(), case.types().1),
            ] {
                let packet = case.packet(direction, kind, code, 77);
                assert_eq!(
                    gate.evaluate_at(direction, PEER, &packet, start + Duration::from_secs(29)),
                    denied(GateReason::Malformed)
                );
            }
        }
        let reply = case.packet(case.reverse(), case.types().1, 0, 77);
        assert_eq!(
            gate.evaluate_at(
                case.reverse(),
                PEER,
                &reply,
                start + Duration::from_secs(31)
            ),
            denied(GateReason::ReverseNewFlow)
        );
    }
}

#[test]
fn echo_code_state_requires_exact_type_identifier_peer_and_direction() {
    for case in cases() {
        let gate = case.gate();
        let request = case.packet(case.request_direction, case.types().0, 0, 77);
        let reply = case.packet(case.reverse(), case.types().1, 0, 77);
        assert_eq!(
            gate.evaluate(case.reverse(), PEER, &reply),
            denied(GateReason::ReverseNewFlow)
        );
        assert_eq!(
            gate.evaluate(
                case.reverse(),
                PEER,
                &case.packet(case.reverse(), case.types().0, 0, 77)
            ),
            denied(GateReason::NoGrant)
        );
        assert_eq!(
            gate.evaluate(case.request_direction, PEER, &request),
            granted("echo")
        );
        for (direction, kind) in [
            (case.reverse(), case.types().0),
            (case.request_direction, case.types().1),
            (case.reverse(), 42),
            (case.request_direction, 42),
        ] {
            assert_eq!(
                gate.evaluate(direction, PEER, &case.packet(direction, kind, 0, 77)),
                denied(GateReason::ReverseNewFlow)
            );
        }
        assert_eq!(
            gate.evaluate(
                case.reverse(),
                PEER,
                &case.packet(case.reverse(), case.types().1, 0, 78)
            ),
            denied(GateReason::ReverseNewFlow)
        );
        assert!(matches!(
            gate.evaluate(case.reverse(), OTHER_PEER, &reply),
            GateDecision::Enforce { allow: false, .. }
        ));
        assert_eq!(
            gate.evaluate(case.request_direction, PEER, &request),
            valid()
        );
        assert_eq!(gate.evaluate(case.reverse(), PEER, &reply), valid());
    }
}

#[test]
fn echo_code_truncated_headers_never_grant_or_reuse_state() {
    for case in cases() {
        let gate = case.gate();
        let request = case.packet(case.request_direction, case.types().0, 0, 77);
        assert_eq!(
            gate.evaluate(case.request_direction, PEER, &request),
            granted("echo")
        );
        for (direction, kind) in [
            (case.request_direction, case.types().0),
            (case.reverse(), case.types().1),
        ] {
            for length in 0..8 {
                let mut packet = case.packet(direction, kind, 0, 77);
                packet.truncate(packet.len() - 8 + length);
                if case.v6 {
                    let payload_len = u16::try_from(packet.len() - 40).unwrap();
                    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
                } else {
                    let total_len = u16::try_from(packet.len()).unwrap();
                    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
                }
                assert_eq!(
                    gate.evaluate(direction, PEER, &packet),
                    denied(GateReason::Malformed)
                );
            }
        }
    }
}

#[test]
fn echo_code_unrelated_nonzero_icmp_errors_and_pmtu_remain_valid() {
    let mut v6 = open_scope6(GateMode::Enforce);
    v6.id = "scope-6".into();
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce), v6]));
    let request = udp(LOCAL, REMOTE, 40000, 53);
    let request6 = udp6(LOCAL6, REMOTE6, 40000, 53);
    assert_eq!(gate.evaluate_outbound(PEER, &request), granted("out"));
    assert_eq!(gate.evaluate_outbound(PEER, &request6), granted("out"));
    let mut pmtu = icmp_error(REMOTE, LOCAL, &request);
    pmtu[21] = 4;
    assert_eq!(gate.evaluate_inbound(PEER, &pmtu), valid());
    let mut error6 = icmp6_error(REMOTE6, LOCAL6, 1, &request6);
    error6[41] = 4;
    assert_eq!(gate.evaluate_inbound(PEER, &error6), valid());
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, 2, &request6)),
        valid()
    );
    let mut other = icmp(REMOTE, LOCAL, 13, 99);
    other[21] = 7;
    assert_eq!(gate.evaluate_inbound(PEER, &other), granted("in"));
}

#[test]
fn echo_code_first_fragments_validate_before_remembering_state() {
    for v6 in [false, true] {
        let case = Echo {
            v6,
            request_direction: PacketDirection::Inbound,
            extensions: false,
        };
        let gate = case.gate();
        let packets = |kind, code, id, reverse| {
            if v6 {
                let (src, dst) = if reverse {
                    (LOCAL6, REMOTE6)
                } else {
                    (REMOTE6, LOCAL6)
                };
                let mut header = icmp_header(kind, 77);
                header[1] = code;
                (
                    ipv6_with(src, dst, &[fragment6(id, 0, true)], 58, &header),
                    ipv6_with(src, dst, &[fragment6(id, 1, false)], 58, &[0; 8]),
                )
            } else {
                let (src, dst) = if reverse {
                    (LOCAL, REMOTE)
                } else {
                    (REMOTE, LOCAL)
                };
                let mut packet = icmp(src, dst, kind, 77);
                packet[21] = code;
                (
                    first_fragment(packet, u16::try_from(id).unwrap()),
                    later_fragment(src, dst, 1, u16::try_from(id).unwrap()),
                )
            }
        };
        let (bad, tail) = packets(case.types().0, 1, 10, false);
        assert_eq!(
            gate.evaluate_inbound(PEER, &bad),
            denied(GateReason::Malformed)
        );
        assert_eq!(
            gate.evaluate_inbound(PEER, &tail),
            denied(GateReason::OrphanFragment)
        );
        assert_eq!(audit_families(&gate), (0, 0));
        let (good, tail) = packets(case.types().0, 0, 11, false);
        assert_eq!(gate.evaluate_inbound(PEER, &good), granted("echo"));
        assert_eq!(gate.evaluate_inbound(PEER, &tail), valid());
        let (bad, tail) = packets(case.types().1, 1, 12, true);
        assert_eq!(
            gate.evaluate_outbound(PEER, &bad),
            denied(GateReason::Malformed)
        );
        assert_eq!(
            gate.evaluate_outbound(PEER, &tail),
            denied(GateReason::OrphanFragment)
        );
        let (good, tail) = packets(case.types().1, 0, 13, true);
        assert_eq!(gate.evaluate_outbound(PEER, &good), valid());
        assert_eq!(gate.evaluate_outbound(PEER, &tail), valid());
    }
}

#[test]
fn echo_code_other_family_types_remain_ordinary_and_cannot_lend_echo_state() {
    for v6 in [false, true] {
        let case = Echo {
            v6,
            request_direction: PacketDirection::Inbound,
            extensions: false,
        };
        let gate = gate_with(policy(vec![if v6 {
            open_scope6(GateMode::Enforce)
        } else {
            open_scope(GateMode::Enforce)
        }]));
        let kind = if v6 { 8 } else { 128 };
        let other = case.packet(PacketDirection::Inbound, kind, 5, 77);
        assert_eq!(gate.evaluate_inbound(PEER, &other), granted("in"));
        assert_eq!(gate.evaluate_inbound(PEER, &other), valid());
        let reply = case.packet(PacketDirection::Outbound, case.types().1, 0, 77);
        assert_eq!(
            gate.evaluate_outbound(PEER, &reply),
            denied(GateReason::ReverseNewFlow)
        );
        let selection = ScopeSelection::one("unrelated".into());
        let request = case.packet(PacketDirection::Inbound, case.types().0, 0, 99);
        assert_eq!(
            gate.evaluate_inbound_in(PEER, &request, &selection)
                .decision,
            denied(GateReason::OutOfScope)
        );
    }
}
