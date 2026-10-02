//! Per-packet cost of the `AclFilter`, inbound and outbound, with the default policy only and
//! with rule namespaces, grants and pinholes.
//!
//! - `default`: no namespaces; a peer in no namespace is evaluated against a few-rule default
//!   policy.
//! - `namespaces`: 8 source namespaces of 64 members each (one restricting outbound traffic), 4
//!   grants and 16 pinholes in one app namespace.
//!
//! Inbound packets open new flows (the filter's reply table holds no allowance for them), so each
//! one is evaluated against the policy.

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

/// Bench `name`: `packet` to or from `peer` through `filter`, which must give `verdict`.
fn bench_packet(
    c: &mut Criterion,
    name: &str,
    filter: &AclFilter,
    peer: PeerId,
    inbound: bool,
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
    c.bench_function(name, |b| b.iter(|| run(std::hint::black_box(&mut buf))));
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
    let outbound = tcp(LOCAL, 22, last_addr, 40000);
    bench_packet(c, "default/outbound", &filter, last, false, &outbound);

    // (b) Namespaces, grants and pinholes.
    let (engine, guards) = namespaces_engine();
    assert_eq!(guards.len(), usize::from(PINHOLES));
    let filter = AclFilter::new(engine, identity());
    bench_packet(c, "namespaces/inbound", &filter, last, true, &inbound);
    let granted = tcp(address(0, 1), 40000, address(1, 1), 443);
    bench_packet(
        c,
        "namespaces/inbound_grant",
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
}

criterion_group!(namespaces, bench_namespaces);
criterion_main!(namespaces);
