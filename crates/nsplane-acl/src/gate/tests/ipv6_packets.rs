//! IPv6 packets: the extension-header walk, fragments, `ICMPv6` errors and
//! echo, and malformed packets.

use super::*;

/// A scope admitting inbound TCP to port 443 only, so a granted SYN proves
/// the ports behind the extension headers were read.
fn web_gate() -> Arc<FlowGate> {
    gate_with(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "web",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![tcp_port(443)],
        )],
    )]))
}

fn syn_with(extensions: &[Extension], src_port: u16, dst_port: u16) -> Vec<u8> {
    ipv6_with(
        REMOTE6,
        LOCAL6,
        extensions,
        6,
        &tcp_header(src_port, dst_port, 0x02),
    )
}

#[test]
fn the_ports_behind_every_extension_header_are_read() {
    let gate = web_gate();
    let chains: [(&str, Vec<Extension>); 7] = [
        ("no extension header", Vec::new()),
        ("Hop-by-Hop", vec![options(0, 1)]),
        ("Routing", vec![options(43, 2)]),
        ("Destination Options", vec![options(60, 3)]),
        ("AH", vec![ah()]),
        ("atomic fragment", vec![fragment6(7, 0, false)]),
        (
            "every kind",
            vec![
                options(0, 1),
                options(60, 1),
                options(43, 1),
                fragment6(8, 0, false),
                ah(),
                options(60, 2),
            ],
        ),
    ];
    for (port, (name, chain)) in (40_000..).zip(chains) {
        assert_eq!(
            gate.evaluate_inbound(PEER, &syn_with(&chain, port, 443)),
            granted("web"),
            "{name}"
        );
        assert_eq!(
            gate.evaluate_inbound(PEER, &syn_with(&chain, port, 22)),
            denied(GateReason::NoGrant),
            "{name}: another port"
        );
    }
    assert_eq!(
        audit_families(&gate),
        (7, 0),
        "an atomic fragment is unfragmented"
    );
}

#[test]
fn at_most_eight_extension_headers_are_walked() {
    let gate = web_gate();
    let eight = vec![options(60, 1); 8];
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn_with(&eight, 40_000, 443)),
        granted("web")
    );
    let nine = vec![options(60, 1); 9];
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn_with(&nine, 40_001, 443)),
        denied(GateReason::Malformed)
    );
    let mut with_fragment = vec![options(60, 1); 8];
    with_fragment.push(fragment6(1, 0, true));
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn_with(&with_fragment, 40_002, 443)),
        denied(GateReason::Malformed),
        "a Fragment header counts"
    );
    let mut with_later_fragment = vec![options(60, 1); 8];
    with_later_fragment.push(fragment6(2, 2, true));
    assert_eq!(
        gate.evaluate_inbound(
            PEER,
            &ipv6_with(REMOTE6, LOCAL6, &with_later_fragment, 6, &[0; 8])
        ),
        denied(GateReason::Malformed),
        "a later fragment's Fragment header counts"
    );
}

#[test]
fn a_later_fragment_as_ninth_header_is_malformed() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    let id = 0x0bad_cafe;
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_000, 53, id)),
        granted("in")
    );
    let mut nine = vec![options(60, 1); 8];
    nine.push(fragment6(id, 2, true));
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv6_with(REMOTE6, LOCAL6, &nine, 17, &[0; 8])),
        denied(GateReason::Malformed)
    );
    let mut eight = vec![options(60, 1); 7];
    eight.push(fragment6(id, 2, true));
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv6_with(REMOTE6, LOCAL6, &eight, 17, &[0; 8])),
        valid(),
        "eight headers, the Fragment header included, are walked"
    );
}

#[test]
fn a_truncated_or_overlong_chain_is_malformed() {
    let gate = web_gate();
    let whole = syn_with(&[options(0, 2)], 40_000, 443);

    // The Hop-by-Hop header claims more bytes than the payload holds.
    let mut overlong = whole.clone();
    overlong[41] = 9;
    assert_eq!(
        gate.evaluate_inbound(PEER, &overlong),
        denied(GateReason::Malformed)
    );
    // The payload ends inside the extension header.
    let mut truncated = whole.clone();
    truncated.truncate(44);
    truncated[4..6].copy_from_slice(&4_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated),
        denied(GateReason::Malformed)
    );
    // The payload ends right after it, without the TCP header.
    let mut headless = whole.clone();
    headless.truncate(56);
    headless[4..6].copy_from_slice(&16_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &headless),
        denied(GateReason::Malformed)
    );
    // The payload length runs past the buffer.
    let mut beyond = whole.clone();
    beyond[4..6].copy_from_slice(&200_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &beyond),
        denied(GateReason::Malformed)
    );
    // A shorter payload length cuts the TCP header.
    let mut short = whole;
    short[4..6].copy_from_slice(&30_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &short),
        denied(GateReason::Malformed)
    );
    assert_eq!(audit_families(&gate), (0, 0));
}

#[test]
fn a_second_fragment_header_is_malformed() {
    let gate = web_gate();
    for chain in [
        vec![fragment6(1, 0, true), fragment6(1, 0, true)],
        vec![
            fragment6(1, 0, false),
            options(60, 1),
            fragment6(2, 0, false),
        ],
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &syn_with(&chain, 40_000, 443)),
            denied(GateReason::Malformed)
        );
    }
}

#[test]
fn a_first_fragment_must_hold_the_whole_upper_layer_header() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    for (protocol, length) in [(6, 19), (17, 7), (58, 7)] {
        let first = ipv6_with(
            REMOTE6,
            LOCAL6,
            &[fragment6(3, 0, true)],
            protocol,
            &vec![1; length],
        );
        assert_eq!(
            gate.evaluate_inbound(PEER, &first),
            denied(GateReason::Malformed),
            "protocol {protocol}"
        );
    }
    let tiny_udp = ipv6(REMOTE6, LOCAL6, 17, &[1; 7]);
    assert_eq!(
        gate.evaluate_inbound(PEER, &tiny_udp),
        denied(GateReason::Malformed),
        "unfragmented too"
    );
    assert_eq!(audit_families(&gate), (0, 0));
}

#[test]
fn esp_and_no_next_header_are_upper_layers_without_ports() {
    let gate = gate_with(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "esp",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Ip(50)],
        )],
    )]));
    let esp = ipv6_with(REMOTE6, LOCAL6, &[options(60, 1)], 50, &[0; 4]);
    assert_eq!(gate.evaluate_inbound(PEER, &esp), granted("esp"));
    assert_eq!(
        gate.evaluate_outbound(PEER, &ipv6(LOCAL6, REMOTE6, 50, &[0; 4])),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv6(REMOTE6, LOCAL6, 59, &[])),
        denied(GateReason::NoGrant)
    );
}

#[test]
pub(super) fn later_ipv6_fragments_need_an_admitted_first_fragment() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    let id = 0x1234_5678;
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_000, 53, id)),
        granted("in")
    );
    assert_eq!(audit_families(&gate), (1, 1));
    assert_eq!(
        gate.evaluate_inbound(PEER, &later_fragment6(REMOTE6, LOCAL6, 17, id)),
        valid()
    );
    let behind_options = ipv6_with(
        REMOTE6,
        LOCAL6,
        &[options(0, 1), fragment6(id, 2, true)],
        17,
        &[0; 8],
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &behind_options),
        valid(),
        "extension headers before the Fragment header"
    );
    for (name, packet) in [
        (
            "another identification",
            later_fragment6(REMOTE6, LOCAL6, 17, id + 1),
        ),
        (
            "the identification's low 16 bits",
            later_fragment6(REMOTE6, LOCAL6, 17, id & 0xffff),
        ),
        (
            "another next header",
            later_fragment6(REMOTE6, LOCAL6, 6, id),
        ),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            denied(GateReason::OrphanFragment),
            "{name}"
        );
    }
    assert_eq!(
        gate.evaluate_outbound(PEER, &later_fragment6(LOCAL6, REMOTE6, 17, id)),
        denied(GateReason::OrphanFragment),
        "fragment state is per direction"
    );
    // A first fragment of an existing flow remembers its fragments too.
    let reply = first_fragment6(LOCAL6, REMOTE6, 53, 40_000, 99);
    assert_eq!(gate.evaluate_outbound(PEER, &reply), valid());
    assert_eq!(
        gate.evaluate_outbound(PEER, &later_fragment6(LOCAL6, REMOTE6, 17, 99)),
        valid()
    );
    assert_eq!(audit_families(&gate), (1, 2));
}

#[test]
fn an_ipv6_fragment_capacity_failure_leaves_no_flow() {
    let gate = limited(16, 16, 0);
    gate.replace(policy(vec![open_scope6(GateMode::Enforce)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_000, 53, 1)),
        denied(GateReason::StateCapacity)
    );
    assert_eq!(audit_families(&gate), (0, 0));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        granted("in")
    );
}

/// A scope where [`PEER`] at [`REMOTE6`] and at `other` may open any flow
/// outbound.
fn outbound_gate(other: Ipv6Addr) -> Arc<FlowGate> {
    let mut scope = scope6("scope-1", GateMode::Enforce, Vec::new());
    scope.bindings.push(binding6(PEER, other, &["remote"]));
    scope.grants.push(grant(
        "out",
        Direction::Outbound,
        &["remote"],
        Vec::new(),
        vec![ProtocolMatch::Any],
    ));
    gate_with(policy(vec![scope]))
}

#[test]
pub(super) fn icmpv6_errors_of_each_type_need_the_quoted_flow() {
    let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
    let gate = outbound_gate(other);
    let original = udp6(LOCAL6, REMOTE6, 50_000, 53);
    assert_eq!(gate.evaluate_outbound(PEER, &original), granted("out"));
    for icmp_type in 1..=4 {
        assert_eq!(
            gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, icmp_type, &original)),
            valid(),
            "type {icmp_type}"
        );
        assert_eq!(
            gate.evaluate_inbound(
                PEER,
                &icmp6_error(
                    REMOTE6,
                    LOCAL6,
                    icmp_type,
                    &udp6(LOCAL6, REMOTE6, 50_001, 53)
                )
            ),
            denied(GateReason::ReverseNewFlow),
            "type {icmp_type}: no flow for the quoted packet"
        );
    }
    // The quote holds the fixed header and 8 bytes of the upper layer, its
    // payload length still the original one.
    let mut long = udp6(LOCAL6, REMOTE6, 50_000, 53);
    long.extend_from_slice(&[0; 100]);
    long[4..6].copy_from_slice(&108_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, 2, &long[..48])),
        valid(),
        "a packet-too-big quoting the start of a long packet"
    );
    // A quoted packet with extension headers.
    let with_options = ipv6_with(
        LOCAL6,
        REMOTE6,
        &[options(60, 1), fragment6(4, 0, true)],
        17,
        &udp_header(50_002, 53),
    );
    assert_eq!(gate.evaluate_outbound(PEER, &with_options), granted("out"));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, 1, &with_options)),
        valid()
    );
    assert_eq!(audit_families(&gate), (2, 1), "errors never create state");
}

#[test]
fn an_unreadable_or_non_mirroring_icmpv6_quote_is_malformed() {
    let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
    let gate = outbound_gate(other);
    let to_other = udp6(LOCAL6, other, 50_002, 53);
    assert_eq!(gate.evaluate_outbound(PEER, &to_other), granted("out"));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, 1, &to_other)),
        denied(GateReason::Malformed),
        "the error's source is not the quoted destination"
    );
    let original = udp6(LOCAL6, REMOTE6, 50_000, 53);
    let mut elsewhere = original.clone();
    elsewhere[8..24].copy_from_slice(&other.octets());
    assert_eq!(gate.evaluate_outbound(PEER, &original), granted("out"));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, 1, &elsewhere)),
        denied(GateReason::Malformed),
        "the error's destination is not the quoted source"
    );
    for (name, quote) in [
        ("an empty quote", Vec::new()),
        ("a fixed header only", original[..40].to_vec()),
        ("7 bytes of the upper layer", original[..47].to_vec()),
        ("an IPv4 quote", udp(LOCAL, REMOTE, 50_000, 53)),
        (
            "a truncated chain",
            ipv6_with(LOCAL6, REMOTE6, &[options(0, 4)], 17, &udp_header(1, 2))[..56].to_vec(),
        ),
        ("a later fragment", later_fragment6(LOCAL6, REMOTE6, 17, 9)),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &icmp6_error(REMOTE6, LOCAL6, 3, &quote)),
            denied(GateReason::Malformed),
            "{name}"
        );
    }
    assert_eq!(audit_families(&gate), (2, 0));
}

#[test]
fn icmpv6_echo_flows_use_the_identifier_and_reverse_types_never_open() {
    let gate = gate_with(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![
            grant(
                "ping",
                Direction::Inbound,
                &["remote"],
                Vec::new(),
                vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![128]))],
            ),
            grant(
                "out",
                Direction::Outbound,
                &["remote"],
                Vec::new(),
                vec![ProtocolMatch::Icmp(IcmpTypes::Any)],
            ),
        ],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6(REMOTE6, LOCAL6, 128, 77)),
        granted("ping")
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &icmp6(LOCAL6, REMOTE6, 129, 77)),
        valid(),
        "the echo reply of the flow"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &icmp6(LOCAL6, REMOTE6, 129, 78)),
        denied(GateReason::ReverseNewFlow),
        "an echo reply without state"
    );
    for icmp_type in [1, 2, 3, 4, 129, 137] {
        let packet = icmp6(REMOTE6, LOCAL6, icmp_type, 79);
        let expected = if icmp_type <= 4 {
            // An error quoting nothing readable.
            denied(GateReason::Malformed)
        } else {
            denied(GateReason::ReverseNewFlow)
        };
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            expected,
            "type {icmp_type}"
        );
        assert_eq!(
            gate.evaluate_outbound(PEER, &icmp6(LOCAL6, REMOTE6, icmp_type, 80)),
            if icmp_type <= 4 {
                denied(GateReason::Malformed)
            } else {
                denied(GateReason::ReverseNewFlow)
            },
            "type {icmp_type} outbound under a grant of every type"
        );
    }
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6(REMOTE6, LOCAL6, 8, 81)),
        denied(GateReason::NoGrant),
        "the ICMPv4 echo type is not an ICMPv6 echo"
    );
}

#[test]
fn neighbor_discovery_is_an_ordinary_icmpv6_flow() {
    let gate = gate_with(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "ping",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![128]))],
        )],
    )]));
    for icmp_type in [130, 133, 134, 135, 136, 143] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &icmp6(REMOTE6, LOCAL6, icmp_type, 0)),
            denied(GateReason::NoGrant),
            "type {icmp_type} fails closed without a grant"
        );
    }
    gate.replace(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "ndp",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![135, 136]))],
        )],
    )]))
    .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6(REMOTE6, LOCAL6, 135, 0)),
        granted("ndp")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp6(REMOTE6, LOCAL6, 133, 1)),
        denied(GateReason::NoGrant)
    );
}

#[test]
fn malformed_ipv6_packets_are_decided_by_the_governing_scopes() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    let mut truncated = tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02);
    truncated.truncate(50);
    truncated[4..6].copy_from_slice(&10_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated),
        denied(GateReason::Malformed)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 0, 22, 0x02)),
        denied(GateReason::Malformed),
        "TCP from port 0"
    );
    let mut elsewhere = truncated.clone();
    elsewhere[24..40].copy_from_slice(&Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1).octets());
    assert_eq!(
        gate.evaluate_inbound(PEER, &elsewhere),
        GateDecision::Pass,
        "a destination no scope governs"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated[..39]),
        GateDecision::Pass,
        "an unreadable packet"
    );

    let mut outbound = tcp6(LOCAL6, REMOTE6, 22, 40_000, 0x12);
    outbound.truncate(50);
    outbound[4..6].copy_from_slice(&10_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_outbound(PEER, &outbound),
        denied(GateReason::Malformed)
    );
    outbound[24..40].copy_from_slice(&Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1).octets());
    assert_eq!(gate.evaluate_outbound(PEER, &outbound), GateDecision::Pass);

    gate.replace(policy(vec![open_scope6(GateMode::Observe)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated),
        observe(false, GateReason::Malformed, None)
    );
}

#[test]
fn an_inert_gate_passes_ipv6_without_parsing() {
    let gate = FlowGate::with_clock(GateConfig::default(), || {
        panic!("an inert gate never reads the clock")
    });
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02)),
        GateDecision::Pass
    );
    assert_eq!(gate.evaluate_outbound(PEER, &[0x60]), GateDecision::Pass);
}

#[test]
fn packets_of_other_versions_pass_an_ipv6_policy() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    for packet in [vec![0x50; 60], vec![0x70; 60], Vec::new()] {
        assert_eq!(gate.evaluate_inbound(PEER, &packet), GateDecision::Pass);
    }
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        GateDecision::Pass,
        "IPv4 to an address the IPv6 scope does not govern"
    );
    assert_eq!(gate.counters(), GateCounters::default());
}
