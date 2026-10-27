//! Per-packet cost of the flow gate: an established inbound flow through `GateFilter` and
//! through `FlowGate::evaluate_inbound` alone, new flows under a grant of every protocol and
//! under a port grant, the `AclFilter` alone as the baseline without the gate, and the
//! established flow while a writer thread keeps replacing the policy.
//!
//! The policy is one enforcing scope compiled the way a product with owner and per-source
//! grants would: the remote binding carries a source label and an owner label, and the grant
//! list starts with the owner grants (inbound to the local address, outbound to any), then
//! the per-source grants.
//!
//! - `established/filter`: one repeated TCP ACK of a flow the inbound owner grant admitted,
//!   through `GateFilter` (with an accept-all `AclFilter` behind it, which an enforced allow
//!   skips).
//! - `established/gate`: the same packet through `FlowGate::evaluate_inbound`.
//! - `established/outbound`: the local reply of that flow through
//!   `FlowGate::evaluate_outbound`.
//! - `scoped/established`: the same packet through `FlowGate::evaluate_inbound_in` with a
//!   selection of the flow's scope; `scoped/out_of_scope`: with a selection of another scope
//!   (an enforced `OutOfScope` denial).
//! - `new_flow/any_grant`, `new_flow/port_grant`: a SYN with a new source port per packet,
//!   admitted by a source grant of every protocol to the local address and by a source grant
//!   of one TCP port (not suspended), each after the two owner grants that do not match. The
//!   gate is rebuilt, untimed, every [`NEW_FLOW_CHUNK`] packets so the per-peer limit (2,048)
//!   is never reached.
//! - `baseline/acl_established`: the same packet through the `AclFilter` alone (no gate);
//!   `baseline/pass_filter`: through `GateFilter` whose gate has no policy, so the packet goes
//!   on to the `AclFilter`; `baseline/pass_gate`: through `FlowGate::evaluate_inbound` of that
//!   gate alone.
//! - `contention/{1ms,10ms}`: `established/filter` while a thread replaces the policy every 1
//!   or 10 ms, toggling a grant for an unrelated source in the same scope (a changed scope,
//!   whose flows are re-authorized).
//!
//! IPv6, with the same scope also governing an IPv6 local address and binding the remote and
//! the unrelated source at IPv6 addresses (the grants to the local address name both):
//!
//! - `established/gate_v6`, `established/outbound_v6`: `established/gate` and
//!   `established/outbound` over IPv6.
//! - `established/extension_chain_v6`: the same ACK behind eight Destination Options headers,
//!   the most the gate walks.
//! - `new_flow/any_grant_v6`: `new_flow/any_grant` over IPv6.
//! - `fragment/later_v6`: a later fragment of an admitted first UDP fragment.
//! - `icmp_error/v6`: an `ICMPv6` destination-unreachable error quoting an outbound UDP flow.
//!
//! The fragment and error benches run on a frozen clock, so their state never expires.
//!
//! The scenarios of the former `benches/node_l3.rs`, like for like:
//!
//! | Former scenario | Here |
//! | --- | --- |
//! | `established/filter`, `established/gate`, `established/outbound` | same names |
//! | `new_flow/node_grant` | `new_flow/any_grant` |
//! | `new_flow/service_grant` | `new_flow/port_grant` |
//! | `baseline/acl_established` | same name |
//! | `baseline/legacy_filter`, `baseline/legacy_gate` | `baseline/pass_filter`, `baseline/pass_gate` |
//! | `contention/1ms`, `contention/10ms` | same names |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use nsplane_acl::gate::{
    FlowGate, GateBinding, GateConfig, GateDecision, GateFilter, GateGrant, GateMode, GatePolicy,
    GateReason, GateScope, ScopeSelection,
};
use nsplane_acl::{
    AclEngine, AclFilter, Direction, IpNet, Label, LabelSet, PeerLabelMap, PortSet, ProtocolMatch,
    Rule, RuleId, RuleSet,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};

const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const UNRELATED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
const LOCAL6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const REMOTE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const UNRELATED6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
const REMOTE_PEER: PeerId = PeerId::new(1);
const UNRELATED_PEER: PeerId = PeerId::new(2);
const PORT: u16 = 443;
/// New flows per gate in the `new_flow` benches, well below the per-peer limit.
const NEW_FLOW_CHUNK: u64 = 1024;
/// TCP flags.
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

/// An IPv4 TCP packet without options or payload.
fn tcp(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, flags: u8) -> PacketBuf {
    let mut bytes = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    PacketBuf::from_packet(&bytes)
}

/// An IPv6 packet whose `extensions` Destination Options headers (8 bytes each) precede the
/// upper layer `protocol` carrying `payload`.
fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, extensions: usize, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(extensions * 8 + payload.len()).unwrap_or(u16::MAX);
    let first = if extensions == 0 { protocol } else { 60 };
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&[first, 64]);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    for index in 0..extensions {
        let next = if index + 1 == extensions {
            protocol
        } else {
            60
        };
        bytes.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
    }
    bytes.extend_from_slice(payload);
    bytes
}

/// A TCP header without options of an IPv6 packet behind `extensions` extension headers.
fn tcp6(
    src: Ipv6Addr,
    src_port: u16,
    dst: Ipv6Addr,
    dst_port: u16,
    flags: u8,
    extensions: usize,
) -> PacketBuf {
    let mut header = Vec::new();
    header.extend_from_slice(&src_port.to_be_bytes());
    header.extend_from_slice(&dst_port.to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
    header.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    PacketBuf::from_packet(&ipv6(src, dst, extensions, 6, &header))
}

/// A UDP header and 8 bytes of payload.
fn udp_payload(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&[0, 16, 0, 0]);
    bytes.extend_from_slice(&[0; 8]);
    bytes
}

/// A UDP fragment behind a Fragment header (`offset` in 8-byte units; more fragments follow).
fn udp6_fragment(src: Ipv6Addr, dst: Ipv6Addr, offset: u16, payload: &[u8]) -> PacketBuf {
    let mut bytes = vec![17, 0];
    bytes.extend_from_slice(&((offset << 3) | 1).to_be_bytes());
    bytes.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
    bytes.extend_from_slice(payload);
    PacketBuf::from_packet(&ipv6(src, dst, 0, 44, &bytes))
}

fn host(ip: Ipv4Addr) -> IpNet {
    format!("{ip}/32")
        .parse()
        .unwrap_or_else(|_| unreachable!())
}

fn binding(peer: PeerId, ip: Ipv4Addr, source: &str, owner: &str) -> GateBinding {
    GateBinding {
        peer,
        addresses: vec![IpAddr::V4(ip)],
        labels: LabelSet::new([Label::from(source), Label::from(owner)]),
    }
}

fn grant(
    id: &str,
    direction: Direction,
    label: &str,
    destinations: Vec<IpNet>,
    protocols: Vec<ProtocolMatch>,
) -> GateGrant {
    GateGrant {
        id: id.into(),
        direction,
        labels: vec![Label::from(label)],
        destinations,
        protocols,
        suspended: false,
    }
}

/// The owner grants, then the inbound `source_grants` (for the source label `source`).
fn grants(source_grants: &[(&str, &str, Vec<ProtocolMatch>)]) -> Vec<GateGrant> {
    let mut grants = vec![
        grant(
            "owner",
            Direction::Inbound,
            "owner:local",
            vec![host(LOCAL)],
            vec![ProtocolMatch::Any],
        ),
        grant(
            "owner",
            Direction::Outbound,
            "owner:local",
            Vec::new(),
            vec![ProtocolMatch::Any],
        ),
    ];
    for (id, source, protocols) in source_grants {
        grants.push(grant(
            id,
            Direction::Inbound,
            source,
            vec![host(LOCAL)],
            protocols.clone(),
        ));
    }
    grants
}

/// One enforcing scope at the local address binding the remote source (of the local owner
/// when `same_owner`) and an unrelated one, with `grants`.
fn policy(same_owner: bool, grants: Vec<GateGrant>) -> GatePolicy {
    let owner = if same_owner {
        "owner:local"
    } else {
        "owner:remote"
    };
    GatePolicy {
        scopes: vec![GateScope {
            id: "scope-1".into(),
            mode: GateMode::Enforce,
            local: vec![IpAddr::V4(LOCAL)],
            bindings: vec![
                binding(REMOTE_PEER, REMOTE, "source:remote", owner),
                binding(
                    UNRELATED_PEER,
                    UNRELATED,
                    "source:unrelated",
                    "owner:unrelated",
                ),
            ],
            unbound_addresses: Vec::new(),
            grants,
            unbound: Vec::new(),
        }],
        holds: nsplane_acl::gate::GateHolds::default(),
    }
}

/// `policy` with its scope also governing [`LOCAL6`], binding the remote and the unrelated
/// source at [`REMOTE6`] and [`UNRELATED6`], and its grants to [`LOCAL`] also naming
/// [`LOCAL6`].
fn dual_stack(mut policy: GatePolicy) -> GatePolicy {
    let local6 = format!("{LOCAL6}/128")
        .parse::<IpNet>()
        .unwrap_or_else(|_| unreachable!());
    for scope in &mut policy.scopes {
        scope.local.push(IpAddr::V6(LOCAL6));
        scope.bindings[0].addresses.push(IpAddr::V6(REMOTE6));
        scope.bindings[1].addresses.push(IpAddr::V6(UNRELATED6));
        for grant in &mut scope.grants {
            if grant.destinations == [host(LOCAL)] {
                grant.destinations.push(local6);
            }
        }
    }
    policy
}

/// A gate with `policy` published, on a clock frozen at its creation.
fn frozen_gate(policy: GatePolicy) -> Arc<FlowGate> {
    let start = Instant::now();
    let gate = FlowGate::with_clock(GateConfig::default(), move || start);
    assert!(gate.replace(policy).is_ok());
    gate
}

/// A gate with `policy` published.
fn gate(policy: GatePolicy) -> Arc<FlowGate> {
    let gate = FlowGate::new(GateConfig::default());
    assert!(gate.replace(policy).is_ok());
    gate
}

/// An `AclFilter` accepting everything from the remote peer.
fn accept_acl() -> AclFilter {
    let engine = Arc::new(AclEngine::new());
    let rules = RuleSet::new([Rule::new(
        "all",
        vec![
            ProtocolMatch::Tcp(PortSet::Any),
            ProtocolMatch::Udp(PortSet::Any),
        ],
    )]);
    assert!(rules.is_ok());
    engine.install(rules.unwrap_or_else(|_| RuleSet::empty()));
    let identities = Arc::new(PeerLabelMap::new());
    identities.insert(REMOTE_PEER, LabelSet::new([Label::from("remote")]));
    AclFilter::new(engine, identities)
}

/// Bench `name`: `packet` repeated inbound through `filter`, which must accept it.
fn bench_filter(c: &mut Criterion, name: &str, filter: &impl PacketFilter, packet: &PacketBuf) {
    assert_eq!(
        filter.inbound(REMOTE_PEER, &mut packet.clone()),
        Verdict::Accept,
        "{name}"
    );
    let mut buf = packet.clone();
    c.bench_function(name, |b| {
        b.iter(|| filter.inbound(REMOTE_PEER, std::hint::black_box(&mut buf)));
    });
}

/// The SYN opening the established flow and its repeated ACK.
fn established_packets() -> (PacketBuf, PacketBuf) {
    (
        tcp(REMOTE, 40000, LOCAL, 22, SYN),
        tcp(REMOTE, 40000, LOCAL, 22, ACK),
    )
}

/// Bench `name`: SYNs with a new source port each to `dst_port` through fresh gates built by
/// `make_gate`, [`NEW_FLOW_CHUNK`] packets per gate.
fn bench_new_flows(
    c: &mut Criterion,
    name: &str,
    make_gate: impl Fn() -> Arc<FlowGate>,
    dst_port: u16,
) {
    let packet = tcp(REMOTE, 1024, LOCAL, dst_port, SYN);
    c.bench_function(name, |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            let mut done = 0;
            while done < iters {
                let gate = make_gate();
                let chunk = NEW_FLOW_CHUNK.min(iters - done);
                let mut buf = packet.clone();
                let start = Instant::now();
                for port in 0..chunk {
                    let port = u16::try_from(port + 1024).unwrap_or(u16::MAX);
                    // The TCP source port, after the 20-byte IPv4 header.
                    buf.as_packet_mut()[20..22].copy_from_slice(&port.to_be_bytes());
                    std::hint::black_box(
                        gate.evaluate_inbound(REMOTE_PEER, std::hint::black_box(buf.as_packet())),
                    );
                }
                elapsed += start.elapsed();
                done += chunk;
            }
            elapsed
        });
    });
}

/// [`bench_new_flows`] over IPv6.
fn bench_new_flows_v6(c: &mut Criterion, name: &str, make_gate: impl Fn() -> Arc<FlowGate>) {
    let packet = tcp6(REMOTE6, 1024, LOCAL6, 22, SYN, 0);
    c.bench_function(name, |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            let mut done = 0;
            while done < iters {
                let gate = make_gate();
                let chunk = NEW_FLOW_CHUNK.min(iters - done);
                let mut buf = packet.clone();
                let start = Instant::now();
                for port in 0..chunk {
                    let port = u16::try_from(port + 1024).unwrap_or(u16::MAX);
                    // The TCP source port, after the 40-byte IPv6 header.
                    buf.as_packet_mut()[40..42].copy_from_slice(&port.to_be_bytes());
                    std::hint::black_box(
                        gate.evaluate_inbound(REMOTE_PEER, std::hint::black_box(buf.as_packet())),
                    );
                }
                elapsed += start.elapsed();
                done += chunk;
            }
            elapsed
        });
    });
}

/// Bench `name`: `packet` repeated through `gate` in `direction`, which must allow it.
fn bench_allowed(
    c: &mut Criterion,
    name: &str,
    gate: &FlowGate,
    inbound: bool,
    packet: &PacketBuf,
) {
    let evaluate = |packet: &[u8]| {
        if inbound {
            gate.evaluate_inbound(REMOTE_PEER, packet)
        } else {
            gate.evaluate_outbound(REMOTE_PEER, packet)
        }
    };
    assert!(
        matches!(
            evaluate(packet.as_packet()),
            GateDecision::Enforce { allow: true, .. }
        ),
        "{name}"
    );
    c.bench_function(name, |b| {
        b.iter(|| evaluate(std::hint::black_box(packet.as_packet())));
    });
}

/// The IPv6 benches.
fn bench_ipv6(c: &mut Criterion) {
    let established = gate(dual_stack(policy(true, grants(&[]))));
    let syn = tcp6(REMOTE6, 40000, LOCAL6, 22, SYN, 0);
    assert!(matches!(
        established.evaluate_inbound(REMOTE_PEER, syn.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    let ack = tcp6(REMOTE6, 40000, LOCAL6, 22, ACK, 0);
    bench_allowed(c, "established/gate_v6", &established, true, &ack);
    let reply = tcp6(LOCAL6, 22, REMOTE6, 40000, ACK, 0);
    bench_allowed(c, "established/outbound_v6", &established, false, &reply);
    let chained = tcp6(REMOTE6, 40000, LOCAL6, 22, ACK, 8);
    bench_allowed(
        c,
        "established/extension_chain_v6",
        &established,
        true,
        &chained,
    );

    let any_grant = || {
        gate(dual_stack(policy(
            false,
            grants(&[("any", "source:remote", vec![ProtocolMatch::Any])]),
        )))
    };
    let probe = tcp6(REMOTE6, 1, LOCAL6, 22, SYN, 0);
    assert!(matches!(
        any_grant().evaluate_inbound(REMOTE_PEER, probe.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    bench_new_flows_v6(c, "new_flow/any_grant_v6", any_grant);

    let fragments = frozen_gate(dual_stack(policy(true, grants(&[]))));
    let first = udp6_fragment(REMOTE6, LOCAL6, 0, &udp_payload(40000, 53));
    assert!(matches!(
        fragments.evaluate_inbound(REMOTE_PEER, first.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    let later = udp6_fragment(REMOTE6, LOCAL6, 2, &[0; 16]);
    bench_allowed(c, "fragment/later_v6", &fragments, true, &later);

    let errors = frozen_gate(dual_stack(policy(true, grants(&[]))));
    let original = ipv6(LOCAL6, REMOTE6, 0, 17, &udp_payload(50000, 53));
    assert!(matches!(
        errors.evaluate_outbound(REMOTE_PEER, &original),
        GateDecision::Enforce { allow: true, .. }
    ));
    let mut unreachable = vec![1, 0, 0, 0, 0, 0, 0, 0];
    unreachable.extend_from_slice(&original);
    let error = PacketBuf::from_packet(&ipv6(REMOTE6, LOCAL6, 0, 58, &unreachable));
    bench_allowed(c, "icmp_error/v6", &errors, true, &error);
}

/// Without the gate: the ACL filter alone, and a gate without a policy in front of it and
/// alone.
fn bench_baselines(c: &mut Criterion, syn: &PacketBuf, ack: &PacketBuf) {
    let acl = accept_acl();
    assert_eq!(acl.inbound(REMOTE_PEER, &mut syn.clone()), Verdict::Accept);
    bench_filter(c, "baseline/acl_established", &acl, ack);
    let pass_gate = FlowGate::new(GateConfig::default());
    let pass = GateFilter::new(Arc::clone(&pass_gate)).with_acl(accept_acl());
    assert_eq!(pass.inbound(REMOTE_PEER, &mut syn.clone()), Verdict::Accept);
    bench_filter(c, "baseline/pass_filter", &pass, ack);
    assert_eq!(
        pass_gate.evaluate_inbound(REMOTE_PEER, ack.as_packet()),
        GateDecision::Pass
    );
    c.bench_function("baseline/pass_gate", |b| {
        b.iter(|| pass_gate.evaluate_inbound(REMOTE_PEER, std::hint::black_box(ack.as_packet())));
    });
}

/// `established/filter` while a thread replaces the policy every `period`.
fn bench_contention(c: &mut Criterion, name: &str, period: Duration) {
    let (mut syn, ack) = established_packets();
    let gate = gate(policy(true, grants(&[])));
    let filter = GateFilter::new(Arc::clone(&gate)).with_acl(accept_acl());
    assert_eq!(filter.inbound(REMOTE_PEER, &mut syn), Verdict::Accept);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (gate, stop) = (Arc::clone(&gate), Arc::clone(&stop));
        thread::spawn(move || {
            let mut published = 0_u64;
            // Publish before checking `stop`, so even the shortest run (a test-mode
            // iteration) publishes at least once.
            loop {
                let unrelated = [(
                    "source:unrelated",
                    "source:unrelated",
                    vec![ProtocolMatch::Any],
                )];
                let toggled = if published.is_multiple_of(2) {
                    &unrelated[..]
                } else {
                    &[]
                };
                assert!(gate.replace(policy(true, grants(toggled))).is_ok());
                published += 1;
                if stop.load(Ordering::Relaxed) {
                    return published;
                }
                thread::sleep(period);
            }
        })
    };
    bench_filter(c, name, &filter, &ack);
    stop.store(true, Ordering::Relaxed);
    let published = writer.join().unwrap_or(0);
    assert!(published > 0, "{name}: the writer published");
    assert_eq!(
        filter.inbound(REMOTE_PEER, &mut ack.clone()),
        Verdict::Accept
    );
}

fn bench_gate(c: &mut Criterion) {
    let (syn, ack) = established_packets();

    // An established flow through the filter.
    let established_gate = gate(policy(true, grants(&[])));
    let filter = GateFilter::new(Arc::clone(&established_gate)).with_acl(accept_acl());
    assert_eq!(
        filter.inbound(REMOTE_PEER, &mut syn.clone()),
        Verdict::Accept
    );
    bench_filter(c, "established/filter", &filter, &ack);

    // The same packet through the gate alone.
    assert!(matches!(
        established_gate.evaluate_inbound(REMOTE_PEER, ack.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    c.bench_function("established/gate", |b| {
        b.iter(|| {
            established_gate.evaluate_inbound(REMOTE_PEER, std::hint::black_box(ack.as_packet()))
        });
    });

    let reply = tcp(LOCAL, 22, REMOTE, 40000, ACK);
    assert!(matches!(
        established_gate.evaluate_outbound(REMOTE_PEER, reply.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    c.bench_function("established/outbound", |b| {
        b.iter(|| {
            established_gate.evaluate_outbound(REMOTE_PEER, std::hint::black_box(reply.as_packet()))
        });
    });

    // The same packet for a selection of its scope and of another one.
    let own = ScopeSelection::one("scope-1".into());
    assert_eq!(
        established_gate
            .evaluate_inbound_in(REMOTE_PEER, ack.as_packet(), &own)
            .rule
            .as_ref()
            .map(RuleId::as_str),
        Some("owner")
    );
    c.bench_function("scoped/established", |b| {
        b.iter(|| {
            established_gate.evaluate_inbound_in(
                REMOTE_PEER,
                std::hint::black_box(ack.as_packet()),
                &own,
            )
        });
    });
    let other = ScopeSelection::one("scope-2".into());
    assert!(matches!(
        established_gate
            .evaluate_inbound_in(REMOTE_PEER, ack.as_packet(), &other)
            .decision,
        GateDecision::Enforce {
            allow: false,
            reason: GateReason::OutOfScope,
            ..
        }
    ));
    c.bench_function("scoped/out_of_scope", |b| {
        b.iter(|| {
            established_gate.evaluate_inbound_in(
                REMOTE_PEER,
                std::hint::black_box(ack.as_packet()),
                &other,
            )
        });
    });

    // New flows under a grant of every protocol and under a port grant.
    let any_grant = || {
        gate(policy(
            false,
            grants(&[("any", "source:remote", vec![ProtocolMatch::Any])]),
        ))
    };
    let probe = tcp(REMOTE, 1, LOCAL, 22, SYN);
    assert!(matches!(
        any_grant().evaluate_inbound(REMOTE_PEER, probe.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    bench_new_flows(c, "new_flow/any_grant", any_grant, 22);
    let port_grant = || {
        gate(policy(
            false,
            grants(&[(
                "port",
                "source:remote",
                vec![ProtocolMatch::Tcp(PortSet::single(PORT))],
            )]),
        ))
    };
    let probe = tcp(REMOTE, 1, LOCAL, PORT, SYN);
    assert!(matches!(
        port_grant().evaluate_inbound(REMOTE_PEER, probe.as_packet()),
        GateDecision::Enforce { allow: true, .. }
    ));
    bench_new_flows(c, "new_flow/port_grant", port_grant, PORT);

    bench_baselines(c, &syn, &ack);

    bench_contention(c, "contention/1ms", Duration::from_millis(1));
    bench_contention(c, "contention/10ms", Duration::from_millis(10));
}

criterion_group!(gate_benches, bench_gate, bench_ipv6);
criterion_main!(gate_benches);
