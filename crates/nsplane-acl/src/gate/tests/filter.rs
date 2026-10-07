//! [`GateFilter`] verdicts: the gate composed with an [`AclFilter`], and the
//! divert of enforced denials.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, PoisonError};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{Ecn, PacketBuf, Path, PeerId, TransportId};

use super::*;
use crate::engine::AclEngine;
use crate::filter::{AclFilter, AclFilterConfig};
use crate::gate::{
    FlowGate, GateBinding, GateConfig, GateCounters, GateGrant, GateHolds, GateMode, GatePolicy,
    GateScope, HoldRule, UnboundAction, UnboundRule,
};
use crate::namespace::{NamespaceMember, NamespacePolicy, OutboundRule};
use crate::net::IpNet;
use crate::pinhole::Direction;
use crate::reasons;
use crate::rules::{Label, LabelSet, PortSet, ProtocolMatch, Rule, RuleSet};

const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const SPOOFED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
const UNBOUND_SOURCE: Ipv4Addr = Ipv4Addr::new(100, 127, 0, 1);
const ELSEWHERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

const PEER: PeerId = PeerId::new(1);
const OTHER: PeerId = PeerId::new(2);
const CARRIER: PeerId = PeerId::new(3);
const UNKNOWN: PeerId = PeerId::new(99);

fn host(ip: Ipv4Addr) -> IpNet {
    format!("{ip}/32").parse().unwrap()
}

fn inbound(filter: &GateFilter, peer: PeerId, packet: &[u8]) -> Verdict {
    let mut buf = PacketBuf::from_packet(packet);
    let verdict = filter.inbound(peer, &mut buf);
    assert_eq!(buf.as_packet(), packet, "the filter never rewrites");
    verdict
}

fn outbound(filter: &GateFilter, peer: PeerId, packet: &[u8]) -> Verdict {
    let mut buf = PacketBuf::from_packet(packet);
    let verdict = filter.outbound(peer, &mut buf);
    assert_eq!(buf.as_packet(), packet, "the filter never rewrites");
    verdict
}

const fn dropped(reason: &'static str) -> Verdict {
    Verdict::Drop { reason }
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..].copy_from_slice(payload);
    packet
}

fn tcp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut header = [0_u8; 20];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[12] = 0x50;
    header[13] = flags;
    ipv4(src, dst, 6, &header)
}

fn udp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut header = [0_u8; 8];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..6].copy_from_slice(&8_u16.to_be_bytes());
    ipv4(src, dst, 17, &header)
}

fn orphan_fragment(src: Ipv4Addr) -> Vec<u8> {
    let mut packet = ipv4(src, LOCAL, 6, &[0; 8]);
    packet[4..6].copy_from_slice(&9_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
    packet
}

fn ipv6_udp() -> Vec<u8> {
    let mut packet = vec![0_u8; 48];
    packet[0] = 0x60;
    packet[5] = 8;
    packet[6] = 17;
    packet[7] = 64;
    let src: std::net::Ipv6Addr = "fd00:9::1".parse().unwrap();
    let dst: std::net::Ipv6Addr = "fd00:5::1".parse().unwrap();
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet[40..42].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&53_u16.to_be_bytes());
    packet[44..46].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

/// One scope at [`LOCAL`] binding [`PEER`] at [`REMOTE`] with `grants`, a
/// pass rule for [`CARRIER`] to TCP 443 and a divert rule for TCP and UDP.
fn scope(mode: GateMode, grants: Vec<GateGrant>) -> GateScope {
    GateScope {
        id: "scope-1".into(),
        mode,
        local: vec![IpAddr::V4(LOCAL)],
        bindings: vec![GateBinding {
            peer: PEER,
            addresses: vec![IpAddr::V4(REMOTE)],
            labels: LabelSet::new([Label::from("remote")]),
        }],
        grants,
        unbound: vec![
            UnboundRule {
                id: "pass".into(),
                peers: vec![CARRIER],
                action: UnboundAction::Pass,
                protocols: vec![ProtocolMatch::Tcp(PortSet::single(443))],
            },
            UnboundRule {
                id: "divert".into(),
                peers: vec![CARRIER],
                action: UnboundAction::Divert,
                protocols: vec![
                    ProtocolMatch::Tcp(PortSet::Any),
                    ProtocolMatch::Udp(PortSet::Any),
                ],
            },
        ],
    }
}

fn web_grant() -> GateGrant {
    GateGrant {
        id: "web".into(),
        direction: Direction::Inbound,
        labels: vec![Label::from("remote")],
        destinations: vec![host(LOCAL)],
        protocols: vec![ProtocolMatch::Tcp(PortSet::single(443))],
        suspended: false,
    }
}

fn out_grant() -> GateGrant {
    GateGrant {
        id: "out".into(),
        direction: Direction::Outbound,
        labels: Vec::new(),
        destinations: Vec::new(),
        protocols: vec![ProtocolMatch::Any],
        suspended: false,
    }
}

fn gate(mode: GateMode) -> Arc<FlowGate> {
    let gate = FlowGate::new(GateConfig::default());
    gate.replace(GatePolicy {
        scopes: vec![scope(mode, vec![web_grant(), out_grant()])],
        holds: GateHolds::default(),
    })
    .unwrap();
    gate
}

fn pass_gate() -> Arc<FlowGate> {
    FlowGate::new(GateConfig::default())
}

/// A divert with room for `capacity` packets, recording what it took.
#[derive(Clone)]
struct Queue {
    taken: Arc<Mutex<Vec<(PeerId, DivertedPacket)>>>,
    capacity: usize,
}

impl Queue {
    fn new(capacity: usize) -> Self {
        Self {
            taken: Arc::default(),
            capacity,
        }
    }

    fn taken(&self) -> std::sync::MutexGuard<'_, Vec<(PeerId, DivertedPacket)>> {
        self.taken.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl GateDivert for Queue {
    fn divert(&self, peer: PeerId, packet: DivertedPacket) -> bool {
        let mut taken = self.taken();
        if taken.len() >= self.capacity {
            return false;
        }
        taken.push((peer, packet));
        true
    }
}

fn label_of(peer: PeerId) -> Label {
    Label::from(format!("peer-{}", peer.get()))
}

fn acl_filter(engine: AclEngine) -> AclFilter {
    let identity = |peer: PeerId| -> Option<LabelSet> {
        [PEER, OTHER, CARRIER]
            .contains(&peer)
            .then(|| LabelSet::new([label_of(peer)]))
    };
    AclFilter::with_config(Arc::new(engine), identity, AclFilterConfig::default())
}

fn acl_with(rules: Vec<Rule>) -> AclFilter {
    let engine = AclEngine::new();
    engine.install(RuleSet::new(rules).unwrap());
    acl_filter(engine)
}

fn accept_acl() -> AclFilter {
    acl_with(vec![Rule::new(
        "all",
        vec![
            ProtocolMatch::Tcp(PortSet::Any),
            ProtocolMatch::Udp(PortSet::Any),
        ],
    )])
}

fn deny_acl() -> AclFilter {
    acl_with(Vec::new())
}

/// An ACL whose only namespace restricts [`PEER`]'s outbound to TCP 443.
fn outbound_restricted_acl() -> AclFilter {
    let engine = AclEngine::new();
    engine
        .store_namespace(
            "team-a",
            NamespacePolicy {
                members: vec![NamespaceMember {
                    label: label_of(PEER),
                    addresses: vec![host(REMOTE)],
                }],
                outbound: Some(vec![OutboundRule::new(
                    "web",
                    vec![ProtocolMatch::Tcp(PortSet::single(443))],
                )]),
                ..NamespacePolicy::default()
            },
        )
        .unwrap();
    acl_filter(engine)
}

#[test]
fn a_gate_without_policy_leaves_every_packet_to_the_acl() {
    let f = GateFilter::new(pass_gate()).with_acl(accept_acl());
    for packet in [
        tcp(REMOTE, LOCAL, 40_000, 22, 0x02),
        udp(REMOTE, LOCAL, 40_000, 53),
        ipv6_udp(),
    ] {
        assert_eq!(inbound(&f, PEER, &packet), Verdict::Accept);
    }
    assert_eq!(f.stats().passed_to_acl, 3);
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_000, 443, 0x02)),
        Verdict::Accept
    );
    let stats = f.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (0, 0));
    assert_eq!(stats.passed_to_acl, 3, "outbound skips the ACL by default");
}

#[test]
fn an_enforced_allow_skips_an_acl_that_would_deny() {
    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(deny_acl());
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 443, 40_000, 0x12)),
        Verdict::Accept
    );
    let stats = f.stats();
    assert_eq!((stats.gate_accepted, stats.passed_to_acl), (2, 0));
}

#[test]
fn enforced_denials_drop_with_the_gate_reason() {
    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(accept_acl());
    for (name, peer, packet, reason) in [
        (
            "no grant",
            PEER,
            tcp(REMOTE, LOCAL, 40_000, 22, 0x02),
            "flow gate: no grant",
        ),
        (
            "reverse new flow",
            PEER,
            tcp(REMOTE, LOCAL, 40_000, 22, 0x10),
            "flow gate: reverse new flow",
        ),
        (
            "spoofed source",
            PEER,
            tcp(SPOOFED, LOCAL, 40_000, 443, 0x02),
            "flow gate: unbound",
        ),
        (
            "a peer the gate does not bind",
            UNKNOWN,
            tcp(REMOTE, LOCAL, 40_000, 443, 0x02),
            "flow gate: unbound",
        ),
        (
            "orphan fragment",
            PEER,
            orphan_fragment(REMOTE),
            "flow gate: orphan fragment",
        ),
    ] {
        assert_eq!(inbound(&f, peer, &packet), dropped(reason), "{name}");
    }
    assert_eq!(
        outbound(&f, OTHER, &tcp(LOCAL, REMOTE, 40_000, 22, 0x02)),
        dropped("flow gate: unbound"),
        "outbound to a bound address over another peer"
    );
    let stats = f.stats();
    assert_eq!((stats.gate_denied, stats.passed_to_acl), (6, 0));
    assert_eq!(f.gate().counters().unbound_denied, 3);
}

#[test]
fn pass_and_observe_fall_through_to_the_acl() {
    let f = GateFilter::new(gate(GateMode::Observe)).with_acl(deny_acl());
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        dropped(reasons::DENIED),
        "an observed denial reaches the ACL"
    );
    assert_eq!(f.gate().counters().observed_denied, 1);

    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(accept_acl());
    assert_eq!(
        inbound(&f, CARRIER, &tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02)),
        Verdict::Accept,
        "an unbound pass rule hands the packet to the ACL"
    );
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, ELSEWHERE, 1, 2, 0x02)),
        Verdict::Accept,
        "an address no scope governs"
    );
    assert_eq!(f.stats().passed_to_acl, 2);
    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(deny_acl());
    assert_eq!(
        inbound(&f, CARRIER, &tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02)),
        dropped(reasons::DENIED),
        "the ACL still decides a passed packet"
    );
}

#[test]
fn the_acl_drops_unknown_peers_off_the_governed_addresses() {
    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(accept_acl());
    assert_eq!(
        inbound(&f, UNKNOWN, &udp(REMOTE, ELSEWHERE, 1, 2)),
        dropped(reasons::UNKNOWN_PEER)
    );
    assert_eq!(
        outbound(&f, UNKNOWN, &udp(LOCAL, ELSEWHERE, 1, 2)),
        Verdict::Accept,
        "outbound off the governed addresses is not the gate's concern"
    );
}

#[test]
fn a_held_packet_drops_in_both_directions() {
    let gate = FlowGate::new(GateConfig::default());
    gate.replace(GatePolicy {
        scopes: vec![scope(GateMode::Observe, vec![web_grant(), out_grant()])],
        holds: GateHolds {
            inbound: vec![HoldRule {
                remote: vec![host(REMOTE)],
                ..HoldRule::default()
            }],
            outbound: vec![HoldRule {
                remote: vec![host(REMOTE)],
                ..HoldRule::default()
            }],
            release: Vec::new(),
        },
    })
    .unwrap();
    let f = GateFilter::new(gate).with_acl(accept_acl());
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02)),
        dropped("flow gate: held")
    );
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_000, 443, 0x02)),
        dropped("flow gate: held")
    );
}

#[test]
fn a_divert_candidate_is_handled_by_the_divert() {
    let queue = Queue::new(8);
    let f = GateFilter::new(gate(GateMode::Enforce))
        .with_acl(accept_acl())
        .with_divert(queue.clone());
    let reply = udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152);
    assert_eq!(inbound(&f, CARRIER, &reply), Verdict::Handled);
    assert_eq!(
        inbound(&f, CARRIER, &orphan_fragment(UNBOUND_SOURCE)),
        Verdict::Handled,
        "an orphan fragment of a divert peer"
    );
    {
        let taken = queue.taken();
        assert_eq!(taken.len(), 2);
        let (peer, packet) = &taken[0];
        assert_eq!(*peer, CARRIER);
        assert_eq!(packet.packet(), reply.as_slice());
        assert_eq!(packet.rule().as_str(), "divert");
        assert_eq!(packet.scope().as_str(), "scope-1");
        assert_eq!(packet.generation(), f.gate().generation());
    }
    let stats = f.stats();
    assert_eq!((stats.diverted, stats.gate_denied), (2, 0));
}

#[test]
fn a_refused_divert_drops() {
    let f = GateFilter::new(gate(GateMode::Enforce)).with_divert(Queue::new(0));
    assert_eq!(
        inbound(&f, CARRIER, &udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152)),
        dropped("flow gate: unbound")
    );
    let stats = f.stats();
    assert_eq!((stats.divert_rejected, stats.gate_denied), (1, 1));
}

#[test]
fn without_a_divert_an_unbound_packet_drops() {
    let f = GateFilter::new(gate(GateMode::Enforce));
    assert_eq!(
        inbound(&f, CARRIER, &udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152)),
        dropped("flow gate: unbound")
    );
}

#[test]
fn other_denials_are_never_diverted() {
    let queue = Queue::new(8);
    let f = GateFilter::new(gate(GateMode::Enforce)).with_divert(queue.clone());
    for (peer, packet) in [
        (PEER, tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        (OTHER, udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152)),
        (CARRIER, udp(REMOTE, LOCAL, 19_999, 49_152)),
    ] {
        assert!(matches!(inbound(&f, peer, &packet), Verdict::Drop { .. }));
    }
    assert!(queue.taken().is_empty());
}

#[test]
fn a_closure_behind_an_arc_is_a_divert() {
    let closure = |_: PeerId, _: DivertedPacket| true;
    let f = GateFilter::new(gate(GateMode::Enforce)).with_divert(Arc::new(closure));
    assert_eq!(
        inbound(&f, CARRIER, &udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152)),
        Verdict::Handled
    );
}

#[test]
fn the_outbound_acl_runs_only_when_opted_in() {
    let packet = tcp(LOCAL, REMOTE, 40_000, 22, 0x02);
    let f = GateFilter::new(pass_gate()).with_acl(outbound_restricted_acl());
    assert_eq!(outbound(&f, PEER, &packet), Verdict::Accept);
    let f = f.with_acl_outbound(true);
    assert_eq!(outbound(&f, PEER, &packet), dropped(reasons::OUTBOUND));
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_001, 443, 0x02)),
        Verdict::Accept
    );
    assert_eq!(f.stats().passed_to_acl, 2);
}

#[test]
fn ipv6_skips_the_gate_and_goes_to_the_acl() {
    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(deny_acl());
    assert_eq!(inbound(&f, PEER, &ipv6_udp()), dropped(reasons::DENIED));
    assert_eq!(f.gate().counters(), GateCounters::default());
}

#[test]
fn inbound_from_runs_the_same_steps() {
    let f = GateFilter::new(gate(GateMode::Enforce)).with_acl(deny_acl());
    let from = Path {
        transport: TransportId::new(0),
        addr: "192.0.2.1:51820".parse().unwrap(),
        ecn: Ecn::NotEct,
    };
    let mut allowed = PacketBuf::from_packet(&tcp(REMOTE, LOCAL, 40_000, 443, 0x02));
    assert_eq!(f.inbound_from(PEER, &from, &mut allowed), Verdict::Accept);
    let mut denied = PacketBuf::from_packet(&tcp(REMOTE, LOCAL, 40_000, 22, 0x02));
    assert_eq!(
        f.inbound_from(PEER, &from, &mut denied),
        dropped("flow gate: no grant")
    );
    let mut passed = PacketBuf::from_packet(&tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02));
    assert_eq!(
        f.inbound_from(CARRIER, &from, &mut passed),
        dropped(reasons::DENIED)
    );
}

#[test]
fn clones_share_state() {
    let f = GateFilter::new(gate(GateMode::Enforce));
    let clone = f.clone();
    let _ = inbound(&clone, PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02));
    assert_eq!(f.stats().gate_denied, 1);
    assert!(Arc::ptr_eq(f.gate(), clone.gate()));
    assert!(format!("{f:?}").contains("GateFilter"));
}
