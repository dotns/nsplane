//! Per-packet cost of the `AclFilter`, inbound and outbound, with the default policy only and
//! with rule namespaces, grants and pinholes.
//!
//! - `default`: no namespaces; a peer in no namespace is evaluated against a three-rule default
//!   rule set (two prefix rules that also need the address label `addr`, which the `k<i>`
//!   labelled peers do not carry). `default/outbound_source_scope` adds an outbound source
//!   constraint (`AclFilterScope::outbound_sources`) the packet passes.
//! - `namespaces`: 8 rule namespaces of 64 member labels each (one restricting outbound
//!   traffic), 4 grants and 16 pinholes in one pinhole namespace.
//! - `bypass`: one namespace of 64 members accepting everything, so its members bypass the
//!   evaluation.
//! - `by_source`: the `default` rules for a peer labelled per source address
//!   (`PeerLabelMap::insert_by_source`), resolved per packet source address.
//! - `other`: the `default` policy and an `ICMPv6` echo request to the local address accepted by
//!   an other-protocol scope rule (`AclFilterScope::other_protocols`).
//! - `stateless`: no reply allowances, allow-only IPv4 fragments (15 s, 4096), `accept_to_local`,
//!   `accept_icmp_echo_reply` and `Ipv6Mode::Accept`, all set explicitly, for a peer with the
//!   address label sending IPv4 TCP to another address than the local one, and a non-first
//!   fragment of a datagram whose first fragment it accepted.
//!
//! `floor` measures what every packet pays before the filter's tables: parsing the five-tuple
//! and loading the engine snapshot.
//!
//! Inbound benches open a new flow with every packet (the source port changes), so each one is
//! evaluated against the policy; `*_established` benches repeat one five-tuple, the established
//! flow the filter's verdict cache serves. Outbound benches repeat one five-tuple.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, AclFilterScope, Direction, FragmentMode, Grant,
    GrantEnd, Ipv6Mode, Label, LabelSet, NamespaceKind, NamespaceMember, NamespacePolicy,
    OtherProtocol, OtherProtocolRule, OutboundRule, PeerLabelMap, PinholeGuard, PinholeSpec,
    PortSet, Protocol, ProtocolMatch, Rule, RuleSet,
};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{IpPacket, PacketBuf, PeerId};

const NAMESPACES: u16 = 8;
const MEMBERS: u16 = 64;
const GRANTS: u16 = 4;
const PINHOLES: u16 = 16;
const LOCAL: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xffff, 0, 0, 0, 0, 0, 1);

/// The peer id of member `i` of namespace `ns`.
fn peer(ns: u16, i: u16) -> PeerId {
    PeerId::new(u32::from(ns) * u32::from(MEMBERS) + u32::from(i) + 1)
}

/// The label of `peer`.
fn label(peer: PeerId) -> Label {
    Label::from(format!("k{}", peer.get()))
}

/// The address label: what the default rules' prefix rules require.
const ADDRESS: &str = "addr";

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

/// An IPv4 TCP packet without options or payload, or with `fragment` (offset in 8-byte units,
/// more fragments) a fragment of datagram 7: a first fragment carries the TCP header, a later
/// one 8 bytes.
fn tcp4(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, fragment: Option<(u16, bool)>) -> PacketBuf {
    let (offset, more) = fragment.unwrap_or((0, false));
    let flags = offset | if more { 0x2000 } else { 0 };
    let len: u16 = if offset > 0 { 28 } else { 40 };
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(&7_u16.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&[64, 6, 0, 0]);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    bytes.extend_from_slice(&40000_u16.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    bytes.truncate(usize::from(len));
    PacketBuf::from_packet(&bytes)
}

/// Three TCP rules: from `10.0.0.0/8` to ports 80 and 443, from `fd00:ffff::/32` to ports
/// 8000-8999, and from anyone to port 22. With `labels`, the prefix rules also need them.
fn three_rules(labels: &[Label]) -> Vec<Rule> {
    vec![
        Rule::new("0", vec![ProtocolMatch::Tcp(PortSet::list([80, 443]))])
            .with_labels(labels.iter().cloned())
            .with_sources("10.0.0.0/8".parse()),
        Rule::new(
            "1",
            vec![ProtocolMatch::Tcp(PortSet::Ranges(vec![
                RangeInclusive::new(8000, 8999),
            ]))],
        )
        .with_labels(labels.iter().cloned())
        .with_sources("fd00:ffff::/32".parse()),
        Rule::new("2", vec![ProtocolMatch::Tcp(PortSet::single(22))]),
    ]
}

/// The default rule set: [`three_rules`] whose prefix rules also need the address label.
fn default_rules() -> RuleSet {
    let rules = RuleSet::new(three_rules(&[Label::from(ADDRESS)]));
    assert!(rules.is_ok());
    rules.unwrap_or_else(|_| RuleSet::empty())
}

/// An engine with [`default_rules`] installed.
fn default_engine() -> Arc<AclEngine> {
    let engine = Arc::new(AclEngine::new());
    engine.install(default_rules());
    engine
}

fn identity() -> Arc<PeerLabelMap> {
    let map = Arc::new(PeerLabelMap::new());
    for ns in 0..NAMESPACES {
        for i in 0..MEMBERS {
            let peer = peer(ns, i);
            map.insert(peer, LabelSet::new([label(peer)]));
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
                    label: label(peer(ns, i)),
                    addresses: address(ns, i).to_string().parse().into_iter().collect(),
                })
                .collect(),
            rules: three_rules(&[]),
            outbound: (ns == 0).then(|| {
                vec![OutboundRule::new(
                    "web",
                    vec![ProtocolMatch::Tcp(PortSet::list([80, 443]))],
                )]
            }),
            pinhole_kinds: ["transfer".to_owned()].into(),
            ..NamespacePolicy::default()
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
            protocols: vec![ProtocolMatch::Tcp(PortSet::single(443))],
        };
        assert!(engine.store_grant(format!("g{g}"), grant).is_ok());
    }
    let session: Vec<PeerId> = (0..PINHOLES).map(|i| peer(i % NAMESPACES, i)).collect();
    let sessions = NamespacePolicy {
        kind: NamespaceKind::Pinholes,
        members: session
            .iter()
            .map(|&peer| NamespaceMember {
                label: label(peer),
                addresses: Vec::new(),
            })
            .collect(),
        ..NamespacePolicy::default()
    };
    assert!(engine.store_namespace("sessions", sessions).is_ok());
    let expires_at = Instant::now() + Duration::from_secs(3600);
    let guards = session
        .iter()
        .map(|&peer| {
            let spec = PinholeSpec {
                label: label(peer),
                kind: "transfer".to_owned(),
                protocol: Protocol::Tcp,
                direction: Direction::Inbound,
                dst_port: 9000,
                expires_at,
            };
            engine.open_pinhole("sessions", spec)
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
    // The TCP source port, after the 20-byte IPv4 or the 40-byte IPv6 header.
    let at = if packet.as_packet()[0] >> 4 == 4 {
        20
    } else {
        40
    };
    c.bench_function(name, |b| {
        b.iter(|| {
            if new_flows {
                port = port.checked_add(1).unwrap_or(1024);
                buf.as_packet_mut()[at..at + 2].copy_from_slice(&port.to_be_bytes());
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
                label: label(peer(0, i)),
                addresses: address(0, i).to_string().parse().into_iter().collect(),
            })
            .collect(),
        rules: vec![Rule::new(
            "all",
            vec![
                ProtocolMatch::Tcp(PortSet::Any),
                ProtocolMatch::Udp(PortSet::Any),
            ],
        )],
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

    // (a) The default rules only.
    let filter = AclFilter::new(default_engine(), identity());
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

    // (d) The floor every filtered packet pays: parsing its five-tuple, and one load of the
    // engine's snapshot (what `generation` reads).
    c.bench_function("floor/five_tuple", |b| {
        b.iter(|| {
            IpPacket::parse(std::hint::black_box(inbound.as_packet()))
                .ok()
                .and_then(|packet| packet.five_tuple())
        });
    });
    let engine = bypass_engine();
    c.bench_function("floor/snapshot", |b| {
        b.iter(|| std::hint::black_box(&engine).generation());
    });
}

/// `default/outbound_source_scope`: `default/outbound` with an outbound source constraint
/// the packet passes.
fn bench_source_scope(c: &mut Criterion) {
    let (last, last_addr) = (
        peer(NAMESPACES - 1, MEMBERS - 1),
        address(NAMESPACES - 1, MEMBERS - 1),
    );
    let engine = default_engine();
    let scope = AclFilterScope::new().with_outbound_sources(
        ["fd00:ffff::/32", "10.0.0.0/8"]
            .iter()
            .filter_map(|prefix| prefix.parse().ok()),
    );
    let filter = AclFilter::with_scope(engine, identity(), AclFilterConfig::default(), scope);
    let outbound = tcp(LOCAL, 22, last_addr, 40000);
    bench_packet(
        c,
        "default/outbound_source_scope",
        &filter,
        last,
        false,
        &outbound,
    );
}

/// `other/icmp_echo_scope`: an inbound `ICMPv6` echo request to the local address, accepted by
/// an `IcmpEcho` scope rule for it.
fn bench_other_scope(c: &mut Criterion) {
    let (last, last_addr) = (
        peer(NAMESPACES - 1, MEMBERS - 1),
        address(NAMESPACES - 1, MEMBERS - 1),
    );
    let engine = default_engine();
    let rule = OtherProtocolRule::new(OtherProtocol::IcmpEcho, format!("{LOCAL}/128").parse());
    let scope = AclFilterScope::new().with_other_protocol(rule);
    let filter = AclFilter::with_scope(engine, identity(), AclFilterConfig::default(), scope);
    let mut bytes = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
    bytes.extend_from_slice(&last_addr.octets());
    bytes.extend_from_slice(&LOCAL.octets());
    bytes.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
    let echo = PacketBuf::from_packet(&bytes);
    bench_established(c, "other/icmp_echo_scope", &filter, last, true, &echo);
}

/// The `by_source` and `stateless` scenarios.
fn bench_by_source(c: &mut Criterion) {
    let (last, last_addr) = (
        peer(NAMESPACES - 1, MEMBERS - 1),
        address(NAMESPACES - 1, MEMBERS - 1),
    );

    // The default rules for a peer labelled per source address.
    let by_source = Arc::new(PeerLabelMap::new());
    let prefix = "fd00::/16".parse().into_iter();
    by_source.insert_by_source(
        last,
        prefix
            .map(|net| (net, LabelSet::new([Label::from(ADDRESS)])))
            .collect(),
    );
    let filter = AclFilter::new(default_engine(), by_source);
    let inbound_v6 = tcp(last_addr, 40000, LOCAL, 22);
    bench_packet(c, "by_source/inbound", &filter, last, true, &inbound_v6);
    bench_established(
        c,
        "by_source/inbound_established",
        &filter,
        last,
        true,
        &inbound_v6,
    );

    // The stateless options for the same peer with the address label, IPv4 TCP from
    // 10.0.0.2 to 10.0.0.3:443 (not the local 10.0.0.1), and a non-first fragment after an
    // accepted first fragment. The engine clock stands still, so the fragment entry never
    // expires.
    let now = Instant::now();
    let engine = Arc::new(AclEngine::with_clock(move || now));
    engine.install(default_rules());
    let address = Arc::new(PeerLabelMap::new());
    address.insert(last, LabelSet::new([Label::from(ADDRESS)]));
    let config = AclFilterConfig {
        allow_other_protocols: false,
        stateful_replies: false,
        fragments: FragmentMode::AllowOnly {
            ttl: Duration::from_secs(15),
            capacity: 4096,
        },
        accept_to_local: Some(Ipv4Addr::new(10, 0, 0, 1)),
        accept_icmp_echo_reply: true,
        ipv6: Ipv6Mode::Accept,
        ..AclFilterConfig::default()
    };
    let filter = AclFilter::with_config(engine, address, config);
    let (src, dst) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
    let tcp_v4 = tcp4(src, dst, 443, None);
    bench_packet(c, "stateless/inbound", &filter, last, true, &tcp_v4);
    bench_established(
        c,
        "stateless/inbound_established",
        &filter,
        last,
        true,
        &tcp_v4,
    );
    let mut first = tcp4(src, dst, 443, Some((0, true)));
    assert_eq!(
        filter.inbound(last, &mut first),
        Verdict::Accept,
        "first fragment"
    );
    let later = tcp4(src, dst, 443, Some((3, true)));
    bench_established(c, "stateless/inbound_fragment", &filter, last, true, &later);
}

criterion_group!(
    namespaces,
    bench_namespaces,
    bench_source_scope,
    bench_other_scope,
    bench_by_source
);
criterion_main!(namespaces);
