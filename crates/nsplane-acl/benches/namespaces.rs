//! Per-packet cost of the `AclFilter`, inbound and outbound, with the default policy only and
//! with rule namespaces, grants and pinholes.
//!
//! - `default`: no namespaces; a peer in no namespace is evaluated against a few-rule default
//!   policy.
//! - `namespaces`: 8 source namespaces of 64 members each (one restricting outbound traffic), 4
//!   grants and 16 pinholes in one app namespace.
//! - `bypass`: one namespace of 64 members accepting everything (a Quick-style namespace), so its
//!   members bypass the evaluation.
//!
//! Inbound benches open a new flow with every packet (the source port changes), so each one is
//! evaluated against the policy; `*_established` benches repeat one five-tuple, the established
//! flow the filter's verdict cache serves. Outbound benches repeat one five-tuple.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, Direction, Grant, GrantEnd,
    NamespaceMember, NamespacePolicy, OutboundRule, PeerIdentityMap, PinholeGuard, PinholeSpec,
    Protocol, SourceAssertion, wg_peer_anchor,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};

const NAMESPACES: u16 = 8;
const MEMBERS: u16 = 64;
const GRANTS: u16 = 4;
const PINHOLES: u16 = 16;
const LOCAL: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xffff, 0, 0, 0, 0, 0, 1);

/// The peer id of member `i` of namespace `ns`.
fn peer(ns: u16, i: u16) -> PeerId {
    PeerId::new(u32::from(ns) * u32::from(MEMBERS) + u32::from(i) + 1)
}

fn key(peer: PeerId) -> [u8; 32] {
    let mut key = [0; 32];
    key[..4].copy_from_slice(&peer.get().to_be_bytes());
    key
}

fn principal(peer: PeerId) -> String {
    wg_peer_anchor(&key(peer))
}

/// The tunnel address of member `i` of namespace `ns`.
const fn address(ns: u16, i: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, ns, 0, 0, 0, 0, 0, i + 1)
}

/// An IPv6 TCP packet without options or payload.
fn tcp(src: Ipv6Addr, src_port: u16, dst: Ipv6Addr, dst_port: u16) -> PacketBuf {
    let mut bytes = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    PacketBuf::from_packet(&bytes)
}

fn rule(src: &str, dst: &str) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec![src.to_owned()],
        dst: vec![dst.to_owned()],
        proto: Some("tcp".to_owned()),
    }
}

fn policy() -> AclPolicy {
    AclPolicy {
        hosts: HashMap::new(),
        acls: vec![
            rule("10.0.0.0/8", "*:80,443"),
            rule("fd00:ffff::/32", "*:8000-8999"),
            rule("*", "*:22"),
        ],
        tests: Vec::new(),
    }
}

fn identity() -> Arc<PeerIdentityMap> {
    let map = Arc::new(PeerIdentityMap::new());
    for ns in 0..NAMESPACES {
        for i in 0..MEMBERS {
            let peer = peer(ns, i);
            map.insert(peer, SourceAssertion::WgPeerKey { pubkey: key(peer) });
        }
    }
    map
}

/// The engine of the `namespaces` scenario, with the pinhole guards keeping it populated.
fn namespaces_engine() -> (Arc<AclEngine>, Vec<PinholeGuard>) {
    let engine = Arc::new(AclEngine::new());
    for ns in 0..NAMESPACES {
        let namespace = NamespacePolicy {
            members: (0..MEMBERS)
                .map(|i| NamespaceMember {
                    principal: principal(peer(ns, i)),
                    addresses: address(ns, i).to_string().parse().into_iter().collect(),
                })
                .collect(),
            policy: policy(),
            outbound: (ns == 0).then(|| {
                vec![OutboundRule {
                    proto: Some("tcp".to_owned()),
                    ports: "80,443".to_owned(),
                }]
            }),
            allow_app_pinholes: ["transfer".to_owned()].into(),
        };
        assert!(
            engine
                .store_namespace(format!("nsd:{ns}"), namespace)
                .is_ok()
        );
    }
    for g in 0..GRANTS {
        let grant = Grant {
            from: GrantEnd::Namespace(format!("nsd:{g}").into()),
            to: GrantEnd::Namespace(format!("nsd:{}", g + 1).into()),
            proto: Some("tcp".to_owned()),
            ports: Some("443".to_owned()),
        };
        assert!(engine.store_grant(format!("g{g}"), grant).is_ok());
    }
    let session: Vec<PeerId> = (0..PINHOLES).map(|i| peer(i % NAMESPACES, i)).collect();
    let app = NamespacePolicy {
        members: session
            .iter()
            .map(|&peer| NamespaceMember {
                principal: principal(peer),
                addresses: Vec::new(),
            })
            .collect(),
        ..NamespacePolicy::default()
    };
    assert!(engine.store_namespace("app:bench", app).is_ok());
    let expires_at = Instant::now() + Duration::from_secs(3600);
    let guards = session
        .iter()
        .map(|&peer| {
            let spec = PinholeSpec {
                peer: principal(peer),
                kind: "transfer".to_owned(),
                protocol: Protocol::Tcp,
                direction: Direction::Inbound,
                dst_port: 9000,
                expires_at,
            };
            engine.open_pinhole("app:bench", spec)
        })
        .collect::<Result<Vec<_>, _>>();
    assert!(guards.is_ok());
    (engine, guards.unwrap_or_default())
}

/// Bench `name`: `packet` to or from `peer` through `filter`, which must accept it. With
/// `new_flows`, the source port changes with every packet.
fn bench_flow(
    c: &mut Criterion,
    name: &str,
    filter: &AclFilter,
    peer: PeerId,
    inbound: bool,
    new_flows: bool,
    packet: &PacketBuf,
) {
    let run = |buf: &mut PacketBuf| {
        if inbound {
            filter.inbound(peer, buf)
        } else {
            filter.outbound(peer, buf)
        }
    };
    assert_eq!(run(&mut packet.clone()), Verdict::Accept, "{name}");
    let mut buf = packet.clone();
    let mut port: u16 = 1024;
    c.bench_function(name, |b| {
        b.iter(|| {
            if new_flows {
                // The TCP source port, after the 40-byte IPv6 header.
                port = port.checked_add(1).unwrap_or(1024);
                buf.as_packet_mut()[40..42].copy_from_slice(&port.to_be_bytes());
            }
            run(std::hint::black_box(&mut buf))
        });
    });
}

/// [`bench_flow`] with new inbound flows or one repeated outbound five-tuple.
fn bench_packet(
    c: &mut Criterion,
    name: &str,
    filter: &AclFilter,
    peer: PeerId,
    inbound: bool,
    packet: &PacketBuf,
) {
    bench_flow(c, name, filter, peer, inbound, inbound, packet);
}

/// [`bench_flow`] with one repeated five-tuple (an established flow).
fn bench_established(
    c: &mut Criterion,
    name: &str,
    filter: &AclFilter,
    peer: PeerId,
    inbound: bool,
    packet: &PacketBuf,
) {
    bench_flow(c, name, filter, peer, inbound, false, packet);
}

/// An engine with one namespace whose 64 members (those of namespace 0) may send anything.
fn bypass_engine() -> Arc<AclEngine> {
    let engine = Arc::new(AclEngine::new());
    let quick = NamespacePolicy {
        members: (0..MEMBERS)
            .map(|i| NamespaceMember {
                principal: principal(peer(0, i)),
                addresses: address(0, i).to_string().parse().into_iter().collect(),
            })
            .collect(),
        policy: AclPolicy {
            hosts: HashMap::new(),
            acls: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".to_owned()],
                dst: vec!["*:*".to_owned()],
                proto: None,
            }],
            tests: Vec::new(),
        },
        ..NamespacePolicy::default()
    };
    assert!(engine.store_namespace("quick", quick).is_ok());
    engine
}

fn bench_namespaces(c: &mut Criterion) {
    // The peer of the last namespace (no pinhole, unrestricted outbound) and one of namespace 0.
    let (last, restricted) = (peer(NAMESPACES - 1, MEMBERS - 1), peer(0, MEMBERS - 1));
    let last_addr = address(NAMESPACES - 1, MEMBERS - 1);
    let restricted_addr = address(0, MEMBERS - 1);

    // (a) The default policy only.
    let engine = Arc::new(AclEngine::new());
    assert!(engine.load(policy()).is_ok());
    let filter = AclFilter::new(engine, identity());
    let inbound = tcp(last_addr, 40000, LOCAL, 22);
    bench_packet(c, "default/inbound", &filter, last, true, &inbound);
    bench_established(
        c,
        "default/inbound_established",
        &filter,
        last,
        true,
        &inbound,
    );
    let outbound = tcp(LOCAL, 22, last_addr, 40000);
    bench_packet(c, "default/outbound", &filter, last, false, &outbound);

    // (b) Namespaces, grants and pinholes.
    let (engine, guards) = namespaces_engine();
    assert_eq!(guards.len(), usize::from(PINHOLES));
    let filter = AclFilter::new(engine, identity());
    bench_packet(c, "namespaces/inbound", &filter, last, true, &inbound);
    bench_established(
        c,
        "namespaces/inbound_established",
        &filter,
        last,
        true,
        &inbound,
    );
    let granted = tcp(address(0, 1), 40000, address(1, 1), 443);
    bench_packet(
        c,
        "namespaces/inbound_grant",
        &filter,
        peer(0, 1),
        true,
        &granted,
    );
    bench_established(
        c,
        "namespaces/inbound_grant_established",
        &filter,
        peer(0, 1),
        true,
        &granted,
    );
    let pinholed = tcp(address(0, 0), 40000, LOCAL, 9000);
    bench_packet(
        c,
        "namespaces/inbound_pinhole",
        &filter,
        peer(0, 0),
        true,
        &pinholed,
    );
    bench_packet(c, "namespaces/outbound", &filter, last, false, &outbound);
    let restricted_out = tcp(LOCAL, 50000, restricted_addr, 443);
    bench_packet(
        c,
        "namespaces/outbound_restricted",
        &filter,
        restricted,
        false,
        &restricted_out,
    );

    // (c) Bypass: a member of a namespace accepting everything.
    let filter = AclFilter::new(bypass_engine(), identity());
    let (member, member_addr) = (peer(0, 5), address(0, 5));
    let inbound = tcp(member_addr, 40000, LOCAL, 443);
    bench_packet(c, "bypass/inbound", &filter, member, true, &inbound);
    bench_established(
        c,
        "bypass/inbound_established",
        &filter,
        member,
        true,
        &inbound,
    );
    let outbound = tcp(LOCAL, 443, member_addr, 40000);
    bench_packet(c, "bypass/outbound", &filter, member, false, &outbound);
}

criterion_group!(namespaces, bench_namespaces);
criterion_main!(namespaces);
