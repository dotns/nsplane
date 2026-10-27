//! Packet filter tests: shared helpers and the basic verdicts.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nsplane_core::{LocalIdentityId, PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId, protocol};

use crate::engine::AclEngine;
use crate::net::{IpNet, Protocol};
use crate::pinhole::{Direction, PinholeGuard, PinholeSpec};
use crate::reasons;
use crate::rules::{LabelSet, PolicyState};

use super::outcome::Outcome;

use std::net::IpAddr;

use super::*;
use crate::namespace::{
    Grant, GrantEnd, NamespaceKind, NamespaceMember, NamespacePolicy, OutboundRule,
};
use crate::rules::{Label, NotInstalled, PortSet, ProtocolMatch, Rule, RuleSet};
use crate::test_packets::{Frag, icmp_echo, ip, ip_frag, tcp, tcp_packet, udp_packet};

mod by_source;
mod bypass;
mod fragments;
mod ipv6;
mod namespaces;
mod other_protocols;
mod pinholes;
mod policy_states;
mod replies;
mod scopes;

const PEER: PeerId = PeerId::new(1);
const OTHER_PEER: PeerId = PeerId::new(2);
const KEY_PEER: PeerId = PeerId::new(3);
/// The label of the peers judged by their source address.
const ADDR: &str = "addr";

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

/// The label of `KEY_PEER`.
fn key_label() -> Label {
    Label::from("key:07")
}

fn label_set(labels: &[&str]) -> LabelSet {
    labels.iter().map(|&label| Label::from(label)).collect()
}

/// Rule `"0"` accepting TCP to `ports` from anyone.
fn tcp_rule(ports: PortSet) -> Rule {
    Rule::new("0", vec![ProtocolMatch::Tcp(ports)])
}

/// Rule `"0"` accepting UDP to `ports` from anyone.
fn udp_rule(ports: PortSet) -> Rule {
    Rule::new("0", vec![ProtocolMatch::Udp(ports)])
}

/// An `ADDR`-labelled source at `10.0.0.1` (or `fd00::1`) may reach
/// `10.0.0.2` TCP 80 (or `fd00::2` TCP 443); a `key_label()` source may
/// reach UDP 53.
fn test_policy() -> RuleSet {
    RuleSet::new([
        Rule::new("0", vec![ProtocolMatch::Tcp(PortSet::single(80))])
            .with_labels([ADDR.into()])
            .with_sources([net("10.0.0.1/32")])
            .with_destinations([net("10.0.0.2/32")]),
        Rule::new("1", vec![ProtocolMatch::Tcp(PortSet::single(443))])
            .with_labels([ADDR.into()])
            .with_sources([net("fd00::1/128")])
            .with_destinations([net("fd00::2/128")]),
        Rule::new("2", vec![ProtocolMatch::Udp(PortSet::single(53))]).with_labels([key_label()]),
    ])
    .unwrap()
}

/// `PEER` and `OTHER_PEER` carry `ADDR` and a label of their own,
/// `KEY_PEER` the key label.
fn identity() -> Arc<PeerLabelMap> {
    let map = Arc::new(PeerLabelMap::new());
    map.insert(PEER, label_set(&[ADDR, "peer-1"]));
    map.insert(OTHER_PEER, label_set(&[ADDR, "peer-2"]));
    map.insert(KEY_PEER, LabelSet::new([key_label()]));
    map
}

/// An engine with `rules` installed whose clock is moved by hand.
fn clocked_engine(rules: RuleSet) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&clock);
    let engine = AclEngine::with_clock(move || *handle.lock().unwrap());
    engine.install(rules);
    (Arc::new(engine), clock)
}

fn advance(clock: &Mutex<Instant>, by: Duration) {
    *clock.lock().unwrap() += by;
}

fn loaded_engine(rules: Vec<Rule>) -> Arc<AclEngine> {
    rules_engine(RuleSet::new(rules).unwrap())
}

fn rules_engine(rules: RuleSet) -> Arc<AclEngine> {
    let engine = Arc::new(AclEngine::new());
    engine.install(rules);
    engine
}

fn filter_with(config: AclFilterConfig) -> AclFilter {
    AclFilter::with_config(rules_engine(test_policy()), identity(), config)
}

fn filter() -> AclFilter {
    filter_with(AclFilterConfig::default())
}

fn inbound(filter: &AclFilter, peer: PeerId, mut packet: PacketBuf) -> Verdict {
    filter.inbound(peer, &mut packet)
}

fn outbound(filter: &AclFilter, peer: PeerId, mut packet: PacketBuf) -> Verdict {
    filter.outbound(peer, &mut packet)
}

fn drop(reason: &'static str) -> Verdict {
    Verdict::Drop { reason }
}

fn deny_all() -> Vec<Rule> {
    Vec::new()
}

/// Sessions and kinds: the pinhole namespace `s1` holds `E` (only there)
/// and `A`; `A` is also in the rule namespace `quick`, which permits
/// "transfer" pinholes.
fn pinhole_engine(
    app_outbound: Option<Vec<OutboundRule>>,
) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&clock);
    let engine = Arc::new(AclEngine::with_clock(move || *handle.lock().unwrap()));
    let mut quick = namespace(&[A], None);
    quick.pinhole_kinds.insert("transfer".to_owned());
    engine.store_namespace("quick", quick).unwrap();
    engine
        .store_namespace(
            "s1",
            NamespacePolicy {
                kind: NamespaceKind::Pinholes,
                members: members(&[A, E]),
                outbound: app_outbound,
                ..NamespacePolicy::default()
            },
        )
        .unwrap();
    (engine, clock)
}

fn open(
    engine: &Arc<AclEngine>,
    clock: &Mutex<Instant>,
    peer: PeerId,
    direction: Direction,
    dst_port: u16,
) -> PinholeGuard {
    let expires_at = *clock.lock().unwrap() + Duration::from_secs(60);
    engine
        .open_pinhole(
            "s1",
            PinholeSpec {
                label: label(peer),
                kind: "transfer".to_owned(),
                protocol: Protocol::Tcp,
                direction,
                dst_port,
                expires_at,
            },
        )
        .unwrap()
}

fn allow_only(capacity: usize) -> AclFilterConfig {
    AclFilterConfig {
        fragments: FragmentMode::AllowOnly {
            ttl: Duration::from_secs(15),
            capacity,
        },
        ..AclFilterConfig::default()
    }
}

fn allowed_len(f: &AclFilter) -> usize {
    f.inner.fragments.lock().unwrap().allowed.len()
}

/// The middle fragment of datagram `id`.
fn continuation(id: u16) -> PacketBuf {
    fragment(id, 4, true, &[0; 8])
}

/// Stateless replies, allow-only fragments (15 s, 4096), `local` in
/// `accept_to_local`, echo replies and IPv6 accepted unevaluated.
fn stateless_options(local: Option<Ipv4Addr>) -> AclFilterConfig {
    AclFilterConfig {
        allow_other_protocols: false,
        stateful_replies: false,
        fragments: allow_only(4096).fragments,
        accept_to_local: local,
        accept_icmp_echo_reply: true,
        ipv6: Ipv6Mode::Accept,
        ..AclFilterConfig::default()
    }
}

const A: PeerId = PeerId::new(11);

const B: PeerId = PeerId::new(12);

const C: PeerId = PeerId::new(13);

const E: PeerId = PeerId::new(15);

const LOCAL: &str = "fd00::1";

fn peer_addr(peer: PeerId) -> IpAddr {
    addr(&format!("fd00::{:x}", peer.get()))
}

fn label(peer: PeerId) -> Label {
    Label::from(format!("k{}", peer.get()))
}

fn members(peers: &[PeerId]) -> Vec<NamespaceMember> {
    peers
        .iter()
        .map(|&peer| NamespaceMember {
            label: label(peer),
            addresses: vec![peer_addr(peer).to_string().parse().unwrap()],
        })
        .collect()
}

/// Members of `peers` may reach each other and the local node on TCP 22.
fn namespace(peers: &[PeerId], outbound: Option<Vec<OutboundRule>>) -> NamespacePolicy {
    NamespacePolicy {
        members: members(peers),
        rules: vec![tcp_rule(PortSet::single(22))],
        outbound,
        ..NamespacePolicy::default()
    }
}

/// Outbound rule `"out"` to `ports`: TCP only when `tcp_only`, else TCP
/// and UDP.
fn outbound_rule(tcp_only: bool, ports: PortSet) -> OutboundRule {
    let mut protocols = vec![ProtocolMatch::Tcp(ports.clone())];
    if !tcp_only {
        protocols.push(ProtocolMatch::Udp(ports));
    }
    OutboundRule::new("out", protocols)
}

/// Identities: the peers of `identity()` plus `A..=E` by their label.
fn ns_identity() -> Arc<PeerLabelMap> {
    let map = identity();
    for peer in [A, B, C, D, E] {
        map.insert(peer, LabelSet::new([label(peer)]));
    }
    map
}

fn ns_filter(engine: &Arc<AclEngine>, config: AclFilterConfig) -> AclFilter {
    AclFilter::with_config(Arc::clone(engine), ns_identity(), config)
}

fn fragment(id: u16, offset_units: u16, more: bool, transport: &[u8]) -> PacketBuf {
    ip_frag(
        addr("10.0.0.1"),
        addr("10.0.0.2"),
        protocol::TCP,
        transport,
        Some(Frag {
            id,
            offset_units,
            more,
        }),
    )
}

fn first_fragment(id: u16, dport: u16) -> PacketBuf {
    fragment(id, 0, true, &tcp(4000, dport, &[0; 8]))
}

/// The local IPv4 address of the scope tests.
const LOCAL4: &str = "10.0.0.2";

/// `A` restricted to outbound TCP 80, in one namespace with `C`.
fn scope_engine() -> Arc<AclEngine> {
    let engine = rules_engine(test_policy());
    engine
        .store_namespace(
            "nsd:a",
            namespace(
                &[A, C],
                Some(vec![outbound_rule(true, PortSet::single(80))]),
            ),
        )
        .unwrap();
    engine
}

fn ipv6_accept() -> AclFilterConfig {
    AclFilterConfig {
        ipv6: Ipv6Mode::Accept,
        ..AclFilterConfig::default()
    }
}

const D: PeerId = PeerId::new(14);

#[test]
fn allowed_and_denied_v4() {
    let f = filter();
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 81)),
        drop(reasons::DENIED)
    );
    // The rule is TCP only.
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 4000, l, 80)),
        drop(reasons::DENIED)
    );
    let stats = f.stats();
    assert_eq!((stats.accepted, stats.denied), (1, 2));
}

#[test]
fn allowed_and_denied_v6() {
    let f = filter();
    let (r, l) = (addr("fd00::1"), addr("fd00::2"));
    let peer6 = PeerId::new(6);
    let map = identity();
    map.insert(peer6, label_set(&[ADDR, "v6"]));
    let f6 = AclFilter::new(rules_engine(test_policy()), map);
    assert_eq!(
        inbound(&f6, peer6, tcp_packet(r, 4000, l, 443)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f6, peer6, tcp_packet(r, 4000, l, 80)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f6, peer6, udp_packet(r, 4000, l, 443)),
        drop(reasons::DENIED)
    );
    // The prefixes read the flow's source address: PEER sending from
    // fd00::1 matches the IPv6 rule too.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 443)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(addr("fd00::9"), 4000, l, 443)),
        drop(reasons::DENIED)
    );
}

#[test]
fn key_label_and_address_label() {
    let f = filter();
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    // The key label matches regardless of the packet's source address.
    assert_eq!(
        inbound(&f, KEY_PEER, udp_packet(r, 5000, l, 53)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(
            &f,
            KEY_PEER,
            udp_packet(addr("fd00::7"), 5000, addr("fd00::2"), 53)
        ),
        Verdict::Accept
    );
    // Without the address label the prefix rule never matches, even from
    // an allowed address.
    assert_eq!(
        inbound(&f, KEY_PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::DENIED)
    );
    // The address label does not match the key rule.
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 5000, l, 53)),
        drop(reasons::DENIED)
    );
}

#[test]
fn unknown_peer_and_empty_labels() {
    let f = filter();
    let packet = || tcp_packet(addr("10.0.0.1"), 4000, addr("10.0.0.2"), 80);
    assert_eq!(
        inbound(&f, PeerId::new(99), packet()),
        drop(reasons::UNKNOWN_PEER)
    );
    assert_eq!(f.stats().unknown_peer, 1);

    // An empty label set is known: it matches label-free rules only.
    let map = Arc::new(PeerLabelMap::new());
    map.insert(PEER, LabelSet::empty());
    let engine = rules_engine(
        RuleSet::new([
            Rule::new("labelled", vec![ProtocolMatch::Tcp(PortSet::single(80))])
                .with_labels([ADDR.into()]),
            Rule::new("free", vec![ProtocolMatch::Tcp(PortSet::single(81))]),
        ])
        .unwrap(),
    );
    let f = AclFilter::new(engine, map);
    assert_eq!(inbound(&f, PEER, packet()), drop(reasons::DENIED));
    assert_eq!(
        inbound(
            &f,
            PEER,
            tcp_packet(addr("10.0.0.1"), 4000, addr("10.0.0.2"), 81)
        ),
        Verdict::Accept
    );
    assert_eq!(f.stats().unknown_peer, 0);
}

#[test]
fn internal_error_is_a_counted_drop() {
    let f = filter();
    let outcome = Outcome::Internal;
    outcome.count(&f.inner.counters);
    assert_eq!(outcome.verdict(), drop(reasons::INTERNAL));
    assert_eq!(f.stats().internal, 1);
    assert_eq!(f.stats().denied, 0);
}

#[test]
fn closure_identity() {
    let identity = |peer: PeerId| (peer == PEER).then(|| LabelSet::new([key_label()]));
    let f = AclFilter::new(rules_engine(test_policy()), identity);
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 5000, l, 53)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, OTHER_PEER, udp_packet(r, 5000, l, 53)),
        drop(reasons::UNKNOWN_PEER)
    );
}

#[test]
fn identity_map_updates_through_shared_handle() {
    let map = identity();
    let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    map.remove(PEER);
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::UNKNOWN_PEER)
    );
}

#[test]
fn no_policy_is_fail_closed_until_loaded() {
    let engine = Arc::new(AclEngine::new());
    let f = AclFilter::new(Arc::clone(&engine), identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::NO_POLICY)
    );
    engine.install(test_policy());
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    engine.uninstall();
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::NO_POLICY)
    );
    let stats = f.stats();
    assert_eq!((stats.no_policy, stats.accepted), (2, 1));
}

#[test]
fn malformed_ipv4_is_dropped() {
    let f = filter();
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, PacketBuf::from_packet(&[0x45, 0, 0])),
        drop(reasons::MALFORMED)
    );
    // Truncated TCP and UDP headers.
    let packet = ip(r, l, protocol::TCP, &[0; 4]);
    assert_eq!(inbound(&f, PEER, packet), drop(reasons::MALFORMED));
    let packet = ip(r, l, protocol::UDP, &[0; 4]);
    assert_eq!(inbound(&f, PEER, packet), drop(reasons::MALFORMED));
    // A total length beyond the buffer or below the header.
    for total in [1000_u16, 12] {
        let mut bytes = tcp_packet(r, 4000, l, 80).as_packet().to_vec();
        bytes[2..4].copy_from_slice(&total.to_be_bytes());
        assert_eq!(
            inbound(&f, PEER, PacketBuf::from_packet(&bytes)),
            drop(reasons::MALFORMED),
            "total length {total}"
        );
    }
    assert_eq!(f.stats().malformed, 5);
}

#[test]
fn fragments_of_a_malformed_first_are_dropped() {
    // `Outcome` gives the later fragments the first one's outcome;
    // `AllowOnly` records nothing for it, so they have no first fragment.
    for (config, later) in [
        (AclFilterConfig::default(), reasons::MALFORMED),
        (allow_only(4096), reasons::FRAGMENT),
    ] {
        let f = filter_with(config);
        // A first fragment too short for its TCP header.
        assert_eq!(
            inbound(&f, PEER, fragment(9, 0, true, &[0; 8])),
            drop(reasons::MALFORMED)
        );
        assert_eq!(inbound(&f, PEER, continuation(9)), drop(later));
        assert_eq!(
            inbound(&f, PEER, fragment(9, 6, false, &[0; 8])),
            drop(later)
        );
    }
}

#[test]
fn icmp_needs_allow_other_protocols() {
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let ping = || ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
    let f = filter();
    assert_eq!(inbound(&f, PEER, ping()), drop(reasons::PROTOCOL));
    assert_eq!(f.stats().protocol, 1);

    let f = filter_with(AclFilterConfig {
        allow_other_protocols: true,
        ..AclFilterConfig::default()
    });
    assert_eq!(inbound(&f, PEER, ping()), Verdict::Accept);
}

#[test]
fn outbound_always_accepts() {
    let engine = Arc::new(AclEngine::new());
    let f = AclFilter::new(engine, identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 80, r, 4000)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, PeerId::new(99), PacketBuf::from_packet(&[1, 2])),
        Verdict::Accept
    );
    assert_eq!(f.stats(), AclFilterStats::default());
}

#[test]
fn clones_share_state() {
    let f = filter();
    let handle = f.clone();
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(handle.stats().accepted, 1);
    outbound(&handle, PEER, tcp_packet(l, 5000, r, 9));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 9, l, 5000)),
        Verdict::Accept
    );
    assert_eq!(handle.stats().replies, 1);
}

#[test]
fn default_config() {
    let config = AclFilterConfig::default();
    assert_eq!(config.fragment_capacity, 1024);
    assert!(!config.allow_other_protocols);
    assert!(config.stateful_replies);
    assert_eq!(config.reply_capacity, 4096);
    assert_eq!(config.reply_idle_timeout, Duration::from_secs(120));
}
