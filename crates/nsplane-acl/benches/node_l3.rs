//! Per-packet cost of the node L3 gate: an established inbound flow through `NodeL3Filter`
//! and through `NodeL3Gate::evaluate_inbound` alone, new flows under a Node and a Service
//! Grant, the `AclFilter` alone as the baseline without the gate, and the established flow
//! while a writer thread keeps publishing new generations.
//!
//! - `established/filter`: one repeated TCP ACK of a same-owner flow through `NodeL3Filter`
//!   (with an accept-all `AclFilter` behind it, which an enforced allow skips).
//! - `established/gate`: the same packet through `NodeL3Gate::evaluate_inbound`.
//! - `established/outbound`: the local reply of that flow through
//!   `NodeL3Gate::evaluate_outbound`.
//! - `new_flow/node_grant`, `new_flow/service_grant`: a SYN with a new source port per packet
//!   under a Node Grant and under a Service Grant (with its Provider listener installed). The
//!   gate is rebuilt, untimed, every [`NEW_FLOW_CHUNK`] packets so the per-peer limit (2,048)
//!   is never reached.
//! - `baseline/acl_established`: the same packet through the `AclFilter` alone (the gate not
//!   installed); `baseline/legacy_filter`: through `NodeL3Filter` whose gate has no snapshot,
//!   so the packet goes on to the `AclFilter`; `baseline/legacy_gate`: through
//!   `NodeL3Gate::evaluate_inbound` of that gate alone.
//! - `contention/{1ms,10ms}`: `established/filter` while a thread applies a new generation
//!   (same content, a Node Grant on an unrelated Node toggled) every 1 or 10 ms.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, NODE_L3_SCHEMA_VERSION, NodeL3Config,
    NodeL3Decision, NodeL3Filter, NodeL3Gate, NodeL3Grant, NodeL3Mode, NodeL3Node,
    NodeL3PeerBinding, NodeL3Resource, NodeL3ServiceEndpoint, NodeL3ServiceProtocol,
    PeerIdentityMap, PeerKeyMap, SourceAssertion,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};

const MACHINE: &str = "machine-1";
const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const UNRELATED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
const REMOTE_KEY: [u8; 32] = [7; 32];
const UNRELATED_KEY: [u8; 32] = [8; 32];
const SERVICE_PORT: u16 = 443;
/// New flows per gate in the `new_flow` benches, well below the per-peer limit.
const NEW_FLOW_CHUNK: u64 = 1024;
/// TCP flags.
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

const fn peer() -> PeerId {
    PeerId::new(1)
}

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

fn node(id: &str, owner: &str, ip: Ipv4Addr) -> NodeL3Node {
    NodeL3Node {
        node_id: id.to_owned(),
        owner_id: owner.to_owned(),
        ip,
    }
}

fn binding(key: [u8; 32], id: &str, owner: &str, ip: Ipv4Addr) -> NodeL3PeerBinding {
    NodeL3PeerBinding {
        peer_public_key: key,
        node_id: id.to_owned(),
        owner_id: owner.to_owned(),
        ip,
    }
}

fn grant(source: &str, resource: NodeL3Resource) -> NodeL3Grant {
    NodeL3Grant {
        grant_id: format!("grant-{source}"),
        source_node_id: source.to_owned(),
        resource,
    }
}

fn node_resource(target: &str) -> NodeL3Resource {
    NodeL3Resource::Node {
        node_id: target.to_owned(),
    }
}

/// An Enforce snapshot of generation `generation`: the local Node, the remote Node (of the
/// local owner when `same_owner`), an unrelated Node, the Service `web` on the local Node and
/// `grants`.
fn config(generation: u64, same_owner: bool, grants: Vec<NodeL3Grant>) -> NodeL3Config {
    let remote_owner = if same_owner {
        "owner-local"
    } else {
        "owner-remote"
    };
    NodeL3Config {
        schema_version: NODE_L3_SCHEMA_VERSION,
        network_id: "network-1".to_owned(),
        target_machine_id: MACHINE.to_owned(),
        generation,
        mode: NodeL3Mode::Enforce,
        local_node: node("node-local", "owner-local", LOCAL),
        bindings: vec![
            binding(REMOTE_KEY, "node-remote", remote_owner, REMOTE),
            binding(
                UNRELATED_KEY,
                "node-unrelated",
                "owner-unrelated",
                UNRELATED,
            ),
        ],
        services: vec![NodeL3ServiceEndpoint {
            service_id: "web".to_owned(),
            node_id: "node-local".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: SERVICE_PORT,
        }],
        grants,
    }
}

/// A gate with `config` applied and the Service listener installed.
fn gate(config: NodeL3Config) -> Arc<NodeL3Gate> {
    let gate = NodeL3Gate::new(MACHINE);
    assert!(gate.apply(config).is_ok());
    gate.replace_provider_listeners(
        MACHINE,
        [("web".to_owned(), NodeL3ServiceProtocol::Tcp, SERVICE_PORT)],
    );
    gate
}

fn keys() -> Arc<PeerKeyMap> {
    let keys = Arc::new(PeerKeyMap::new());
    keys.insert(peer(), REMOTE_KEY);
    keys
}

/// An `AclFilter` accepting everything from the remote peer.
fn accept_acl() -> AclFilter {
    let engine = Arc::new(AclEngine::new());
    let loaded = engine.load(AclPolicy {
        acls: vec![AclRule {
            action: AclAction::Accept,
            src: vec!["*".to_owned()],
            dst: vec!["*:*".to_owned()],
            proto: None,
        }],
        ..AclPolicy::default()
    });
    assert!(loaded.is_ok());
    let identities = Arc::new(PeerIdentityMap::new());
    identities.insert(peer(), SourceAssertion::WgPeerKey { pubkey: REMOTE_KEY });
    AclFilter::new(engine, identities)
}

/// Bench `name`: `packet` repeated inbound through `filter`, which must accept it.
fn bench_filter(c: &mut Criterion, name: &str, filter: &impl PacketFilter, packet: &PacketBuf) {
    assert_eq!(
        filter.inbound(peer(), &mut packet.clone()),
        Verdict::Accept,
        "{name}"
    );
    let mut buf = packet.clone();
    c.bench_function(name, |b| {
        b.iter(|| filter.inbound(peer(), std::hint::black_box(&mut buf)));
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
    make_gate: impl Fn() -> Arc<NodeL3Gate>,
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
                        gate.evaluate_inbound(REMOTE_KEY, std::hint::black_box(buf.as_packet())),
                    );
                }
                elapsed += start.elapsed();
                done += chunk;
            }
            elapsed
        });
    });
}

/// (d) Without the gate: the ACL filter alone, and a gate without a snapshot in front of it
/// and alone.
fn bench_baselines(c: &mut Criterion, syn: &PacketBuf, ack: &PacketBuf) {
    let acl = accept_acl();
    assert_eq!(acl.inbound(peer(), &mut syn.clone()), Verdict::Accept);
    bench_filter(c, "baseline/acl_established", &acl, ack);
    let legacy_gate = NodeL3Gate::new(MACHINE);
    let legacy = NodeL3Filter::new(Arc::clone(&legacy_gate), keys()).with_acl(accept_acl());
    assert_eq!(legacy.inbound(peer(), &mut syn.clone()), Verdict::Accept);
    bench_filter(c, "baseline/legacy_filter", &legacy, ack);
    assert_eq!(
        legacy_gate.evaluate_inbound(REMOTE_KEY, ack.as_packet()),
        NodeL3Decision::Legacy
    );
    c.bench_function("baseline/legacy_gate", |b| {
        b.iter(|| legacy_gate.evaluate_inbound(REMOTE_KEY, std::hint::black_box(ack.as_packet())));
    });
}

fn bench_node_l3(c: &mut Criterion) {
    let (syn, ack) = established_packets();

    // (a) An established flow through the filter.
    let established_gate = gate(config(1, true, Vec::new()));
    let filter = NodeL3Filter::new(Arc::clone(&established_gate), keys()).with_acl(accept_acl());
    assert_eq!(filter.inbound(peer(), &mut syn.clone()), Verdict::Accept);
    bench_filter(c, "established/filter", &filter, &ack);

    // (b) The same packet through the gate alone.
    assert!(matches!(
        established_gate.evaluate_inbound(REMOTE_KEY, ack.as_packet()),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    c.bench_function("established/gate", |b| {
        b.iter(|| {
            established_gate.evaluate_inbound(REMOTE_KEY, std::hint::black_box(ack.as_packet()))
        });
    });

    let reply = tcp(LOCAL, 22, REMOTE, 40000, ACK);
    assert!(matches!(
        established_gate.evaluate_outbound(REMOTE_KEY, reply.as_packet()),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    c.bench_function("established/outbound", |b| {
        b.iter(|| {
            established_gate.evaluate_outbound(REMOTE_KEY, std::hint::black_box(reply.as_packet()))
        });
    });

    // (c) New flows under a Node Grant and under a Service Grant.
    let node_grant = || {
        gate(config(
            1,
            false,
            vec![grant("node-remote", node_resource("node-local"))],
        ))
    };
    let probe = tcp(REMOTE, 1, LOCAL, 22, SYN);
    assert!(matches!(
        node_grant().evaluate_inbound(REMOTE_KEY, probe.as_packet()),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    bench_new_flows(c, "new_flow/node_grant", node_grant, 22);
    let service_grant = || {
        gate(config(
            1,
            false,
            vec![grant(
                "node-remote",
                NodeL3Resource::Service {
                    service_id: "web".to_owned(),
                    node_id: "node-local".to_owned(),
                    protocol: NodeL3ServiceProtocol::Tcp,
                    port: SERVICE_PORT,
                },
            )],
        ))
    };
    let probe = tcp(REMOTE, 1, LOCAL, SERVICE_PORT, SYN);
    assert!(matches!(
        service_grant().evaluate_inbound(REMOTE_KEY, probe.as_packet()),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    bench_new_flows(c, "new_flow/service_grant", service_grant, SERVICE_PORT);

    bench_baselines(c, &syn, &ack);

    // (e) (a) while a writer publishes a new generation every 1 or 10 ms.
    for (name, period) in [
        ("contention/1ms", Duration::from_millis(1)),
        ("contention/10ms", Duration::from_millis(10)),
    ] {
        let gate = gate(config(1, true, Vec::new()));
        let filter = NodeL3Filter::new(Arc::clone(&gate), keys()).with_acl(accept_acl());
        assert_eq!(filter.inbound(peer(), &mut syn.clone()), Verdict::Accept);
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let (gate, stop) = (Arc::clone(&gate), Arc::clone(&stop));
            thread::spawn(move || {
                let mut generation = 1;
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(period);
                    generation += 1;
                    let grants = if generation % 2 == 0 {
                        vec![grant("node-unrelated", node_resource("node-local"))]
                    } else {
                        Vec::new()
                    };
                    assert!(gate.apply(config(generation, true, grants)).is_ok());
                }
                generation
            })
        };
        bench_filter(c, name, &filter, &ack);
        stop.store(true, Ordering::Relaxed);
        let published = writer.join().map_or(0, |generation| generation - 1);
        assert!(published > 0, "{name}: the writer published");
        assert_eq!(filter.inbound(peer(), &mut ack.clone()), Verdict::Accept);
    }
}

criterion_group!(node_l3, bench_node_l3);
criterion_main!(node_l3);
