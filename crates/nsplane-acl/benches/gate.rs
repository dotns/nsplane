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

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use nsplane_acl::gate::{
    FlowGate, GateBinding, GateConfig, GateDecision, GateFilter, GateGrant, GateMode, GatePolicy,
    GateScope,
};
use nsplane_acl::{
    AclEngine, AclFilter, Direction, IpNet, Label, LabelSet, PeerLabelMap, PortSet, ProtocolMatch,
    Rule, RuleSet,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};

const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const UNRELATED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
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

criterion_group!(gate_benches, bench_gate);
criterion_main!(gate_benches);
