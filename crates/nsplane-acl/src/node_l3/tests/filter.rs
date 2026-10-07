//! [`NodeL3Filter`] verdicts, ported from ns
//! `crates/ns/src/account_engine/filters/tests.rs` (`AccountFilter`), plus the
//! composition with [`AclFilter`] and the gateway-consumer divert.
//!
//! The ns tests and where each one lives in nsplane:
//!
//! | ns test | here |
//! | --- | --- |
//! | `permit_all_call_sites` | gate part: [`legacy_gate_leaves_every_packet_to_the_acl`]; local Node, echo reply, ACL fragments: `AclFilter` (MD-A); recovery probe: link layer; IPv6 lease: inbound destinations |
//! | `acl_fails_closed_and_judges_relay_clients_by_key` | not applicable: ACL step (`AclFilter`, its peer identity) |
//! | `dynamic_ipv6_routes` | not applicable: dynamic L3 routes (inbound destinations, routing / MD-6) |
//! | `node_l3_gate` | [`node_l3_gate`] |
//! | `subnet_lan_dns_transport_and_ingress` | transport: [`subnet_transport_admission`]; IPv6 ingress: inbound destinations; route owner: routing / MD-6 |
//! | `gateway_consumer_split` | [`gateway_consumer_split`] |
//! | `peer_keys_are_hot_swappable` | [`peer_keys_are_hot_swappable`] |
//! | `a_relay_client_is_judged_by_its_wireguard_key` | not applicable: ACL step |
//! | `a_peer_outside_the_relay_client_set_is_judged_by_its_source_address` | not applicable: ACL step |
//! | `a_later_fragment_passes_only_after_its_allowed_first_fragment` | not applicable: `AclFilter`'s fragment table |
//! | `a_later_fragment_of_a_denied_first_fragment_is_dropped` | not applicable: `AclFilter`'s fragment table |
//! | `an_icmp_echo_reply_bypasses_the_acl` | not applicable: `AclFilter` (MD-A `accept_icmp_echo_reply`) |
//! | `a_lease_routes_its_prefix_to_its_owner_only` | not applicable: routing / MD-6 |
//! | `overlapping_leases_are_withheld` | not applicable: routing / inbound destinations |
//! | `ipv6_is_admitted_only_in_owned_and_authenticated_return_directions` | not applicable: inbound destinations |
//! | `node_l3_allows_and_denies_with_the_engine_reasons` | [`node_l3_allows_and_denies_with_the_gate_reasons`] |
//! | `a_denied_gateway_return_is_handled_by_the_gateway_consumer` | [`a_denied_gateway_return_is_handled_by_the_gateway_consumer`] |
//! | `enforced_subnet_ipv6_follows_the_grant` | not applicable: inbound destinations and routing; IPv6 here: [`ipv6_skips_the_gate_and_goes_to_the_acl`] |

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{Ecn, PacketBuf, Path, PeerId, TransportId};

use super::*;
use crate::engine::AclEngine;
use crate::filter::{AclFilter, AclFilterConfig};
use crate::namespace::{NamespaceMember, NamespacePolicy, OutboundRule};
use crate::node_l3::{
    NODE_L3_SCHEMA_VERSION, NodeL3Config, NodeL3Grant, NodeL3Mode, NodeL3Node, NodeL3PeerBinding,
    NodeL3PeerPolicyRequirement, NodeL3Resource, NodeL3ServiceEndpoint, NodeL3ServiceProtocol,
    NodeL3Transport, NodeL3TransportPeer,
};
use crate::policy::{AclAction, AclPolicy, AclRule};
use crate::reasons;
use crate::rules::{Label, LabelSet};
use crate::test_packets::udp_packet;

const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const SPOOFED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
const SERVICE_VIP: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 10);
const GATEWAY_TARGET: Ipv4Addr = Ipv4Addr::new(100, 127, 0, 1);

const PEER: [u8; 32] = [7; 32];
const OTHER: [u8; 32] = [8; 32];
const GATEWAY: [u8; 32] = [9; 32];
const KEYS: [[u8; 32]; 3] = [PEER, OTHER, GATEWAY];

/// tunnel-wg `SUBNET_LAN_DNS_TRANSPORT_PORT`, which ns passes.
const SUBNET_TRANSPORT_PORT: u16 = 53_535;
const SUBNET_PREFIX: &str = "fd00:1:2:1:0:7:c0a8:700/120";

fn peer_id(key: [u8; 32]) -> PeerId {
    let index = KEYS.iter().position(|k| *k == key).unwrap();
    PeerId::new(u32::try_from(index).unwrap() + 1)
}

fn peer_keys() -> Arc<PeerKeyMap> {
    let keys = Arc::new(PeerKeyMap::new());
    keys.replace(KEYS.map(|key| (peer_id(key), key)));
    keys
}

fn filter(gate: &Arc<NodeL3Gate>) -> NodeL3Filter {
    NodeL3Filter::new(Arc::clone(gate), peer_keys())
}

fn inbound(filter: &NodeL3Filter, key: [u8; 32], packet: &[u8]) -> Verdict {
    let mut buf = PacketBuf::from_packet(packet);
    let verdict = filter.inbound(peer_id(key), &mut buf);
    assert_eq!(buf.as_packet(), packet, "the filter never rewrites");
    verdict
}

fn outbound(filter: &NodeL3Filter, key: [u8; 32], packet: &[u8]) -> Verdict {
    let mut buf = PacketBuf::from_packet(packet);
    let verdict = filter.outbound(peer_id(key), &mut buf);
    assert_eq!(buf.as_packet(), packet, "the filter never rewrites");
    verdict
}

const fn dropped(reason: &'static str) -> Verdict {
    Verdict::Drop { reason }
}

// ── Packets ──────────────────────────────────────────────────────────────────

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

/// Set the fragment id and offset (in 8-byte units) and the more-fragments flag.
fn fragment(mut packet: Vec<u8>, id: u16, offset: u16, more: bool) -> Vec<u8> {
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = if more { 0x2000 } else { 0 };
    packet[6..8].copy_from_slice(&(flags | offset).to_be_bytes());
    packet
}

fn orphan_fragment() -> Vec<u8> {
    fragment(ipv4(REMOTE, LOCAL, 6, &[0; 8]), 9, 1, false)
}

fn ipv6_udp(dst: &str) -> Vec<u8> {
    let src: IpAddr = "fd00:9::1".parse().unwrap();
    let dst: Ipv6Addr = dst.parse().unwrap();
    udp_packet(src, 40_000, IpAddr::V6(dst), 53)
        .as_packet()
        .to_vec()
}

// ── Gates ────────────────────────────────────────────────────────────────────

fn node_l3_config(mode: NodeL3Mode, same_owner: bool, grants: Vec<NodeL3Grant>) -> NodeL3Config {
    NodeL3Config {
        schema_version: NODE_L3_SCHEMA_VERSION,
        network_id: "network-1".to_owned(),
        target_machine_id: "machine-1".to_owned(),
        generation: 1,
        mode,
        local_node: NodeL3Node {
            node_id: "node-local".to_owned(),
            owner_id: "owner-local".to_owned(),
            ip: LOCAL,
        },
        bindings: vec![NodeL3PeerBinding {
            peer_public_key: PEER,
            node_id: "node-remote".to_owned(),
            owner_id: if same_owner {
                "owner-local".to_owned()
            } else {
                "owner-remote".to_owned()
            },
            ip: REMOTE,
        }],
        services: vec![NodeL3ServiceEndpoint {
            service_id: "service-web".to_owned(),
            node_id: "node-local".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: 443,
        }],
        grants,
    }
}

fn node_projection() -> NodeL3Transport {
    NodeL3Transport {
        local_ip: LOCAL,
        peers: vec![NodeL3TransportPeer {
            public_key: PEER,
            allowed_ips: vec![
                format!("{REMOTE}/32").parse().unwrap(),
                format!("{SERVICE_VIP}/32").parse().unwrap(),
            ],
            gateway_id: None,
            relayed: false,
            node_l3_policy: Some(NodeL3PeerPolicyRequirement {
                network_id: "network-1".to_owned(),
                generation: 1,
                mode: NodeL3Mode::Enforce,
                node_ips: vec![REMOTE],
            }),
        }],
    }
}

/// An enforcing gate with ns's Node projection.
fn node_gate(same_owner: bool, grants: Vec<NodeL3Grant>) -> Arc<NodeL3Gate> {
    let gate = NodeL3Gate::new("machine-1");
    gate.apply(node_l3_config(NodeL3Mode::Enforce, same_owner, grants))
        .unwrap();
    gate.replace_transport_projection(&node_projection())
        .unwrap();
    gate
}

/// An observing gate (no transport projection): it judges but never enforces.
fn observe_gate() -> Arc<NodeL3Gate> {
    let gate = NodeL3Gate::new("machine-1");
    gate.apply(node_l3_config(NodeL3Mode::Observe, false, Vec::new()))
        .unwrap();
    gate
}

/// A gate without a snapshot: every decision is legacy.
fn legacy_gate() -> Arc<NodeL3Gate> {
    NodeL3Gate::new("machine-1")
}

fn subnet_grant(source: &str, routing: &str) -> NodeL3Grant {
    NodeL3Grant {
        grant_id: format!("grant-subnet-{source}"),
        source_node_id: source.to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: routing.to_owned(),
            prefix: SUBNET_PREFIX.parse().unwrap(),
        },
    }
}

/// This Node routes the Subnet; `PEER`'s Node may reach it.
fn subnet_publisher() -> Arc<NodeL3Gate> {
    node_gate(false, vec![subnet_grant("node-remote", "node-local")])
}

/// `PEER`'s Node routes the Subnet; this Node may reach it.
fn subnet_consumer() -> Arc<NodeL3Gate> {
    node_gate(false, vec![subnet_grant("node-local", "node-remote")])
}

/// An enforcing gate whose only peer is the gateway `gw-1` carrying
/// `GATEWAY_TARGET`.
fn gateway_gate() -> Arc<NodeL3Gate> {
    let gate = NodeL3Gate::new("machine-1");
    let mut config = node_l3_config(NodeL3Mode::Enforce, false, Vec::new());
    config.bindings.clear();
    config.services.clear();
    gate.apply(config).unwrap();
    gate.replace_transport_projection(&NodeL3Transport {
        local_ip: LOCAL,
        peers: vec![NodeL3TransportPeer {
            public_key: GATEWAY,
            allowed_ips: vec![format!("{GATEWAY_TARGET}/32").parse().unwrap()],
            gateway_id: Some("gw-1".to_owned()),
            relayed: false,
            node_l3_policy: None,
        }],
    })
    .unwrap();
    gate
}

fn gateway_reply() -> Vec<u8> {
    udp(GATEWAY_TARGET, LOCAL, 19_999, 49_152)
}

/// A sink with room for `capacity` candidates, recording what it took.
#[derive(Clone)]
struct Queue {
    taken: Arc<Mutex<Vec<(PeerId, GatewayConsumerPacket)>>>,
    capacity: usize,
}

impl Queue {
    fn new(capacity: usize) -> Self {
        Self {
            taken: Arc::default(),
            capacity,
        }
    }

    fn taken(&self) -> std::sync::MutexGuard<'_, Vec<(PeerId, GatewayConsumerPacket)>> {
        self.taken.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl GatewayConsumerSink for Queue {
    fn try_divert(&self, peer: PeerId, candidate: GatewayConsumerPacket) -> bool {
        let mut taken = self.taken();
        if taken.len() >= self.capacity {
            return false;
        }
        taken.push((peer, candidate));
        true
    }
}

// ── ACLs ─────────────────────────────────────────────────────────────────────

/// The ACL label of the peer with `key`.
fn key_label(key: &[u8; 32]) -> Label {
    use std::fmt::Write as _;
    let hex = key.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    Label::from(format!("key:{hex}"))
}

fn acl_filter(engine: AclEngine) -> AclFilter {
    let identity = |peer: PeerId| -> Option<LabelSet> {
        KEYS.iter()
            .find(|key| peer_id(**key) == peer)
            .map(|key| LabelSet::new([key_label(key)]))
    };
    AclFilter::with_config(Arc::new(engine), identity, AclFilterConfig::default())
}

fn acl_policy(acls: Vec<AclRule>) -> AclEngine {
    let engine = AclEngine::new();
    engine
        .load(AclPolicy {
            hosts: HashMap::new(),
            acls,
            tests: Vec::new(),
        })
        .unwrap();
    engine
}

/// An ACL accepting everything.
fn accept_acl() -> AclFilter {
    acl_filter(acl_policy(vec![AclRule {
        action: AclAction::Accept,
        src: vec!["*".to_owned()],
        dst: vec!["*:*".to_owned()],
        proto: None,
    }]))
}

/// An ACL denying everything ([`reasons::DENIED`]).
fn deny_acl() -> AclFilter {
    acl_filter(acl_policy(Vec::new()))
}

/// An ACL whose only namespace restricts `PEER`'s outbound to TCP 443.
fn outbound_restricted_acl() -> AclFilter {
    let engine = AclEngine::new();
    engine
        .store_namespace(
            "nsd:a",
            NamespacePolicy {
                members: vec![NamespaceMember {
                    label: key_label(&PEER),
                    addresses: vec![format!("{REMOTE}/32").parse().unwrap()],
                }],
                outbound: Some(vec![OutboundRule {
                    proto: Some("tcp".to_owned()),
                    ports: "443".to_owned(),
                }]),
                ..NamespacePolicy::default()
            },
        )
        .unwrap();
    acl_filter(engine)
}

// ── Ported ns tests ──────────────────────────────────────────────────────────

/// `permit_all_call_sites`, gate part: without a Node L3 snapshot every
/// packet reaches the ACL (here a permit-all one) and every outbound packet
/// is accepted.
#[test]
fn legacy_gate_leaves_every_packet_to_the_acl() {
    let f = filter(&legacy_gate()).with_acl(accept_acl());
    for (name, packet) in [
        (
            "tcp to a service",
            tcp(REMOTE, SERVICE_VIP, 40_000, 443, 0x02),
        ),
        ("udp to a service", udp(REMOTE, SERVICE_VIP, 40_000, 53)),
        ("tcp to the Node", tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        (
            "first fragment",
            fragment(udp(REMOTE, SERVICE_VIP, 40_000, 53), 7, 0, true),
        ),
        ("ipv6", ipv6_udp("fd00:5::1")),
    ] {
        assert_eq!(inbound(&f, PEER, &packet), Verdict::Accept, "{name}");
    }
    assert_eq!(f.stats().passed_to_acl, 5);
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_000, 443, 0x02)),
        Verdict::Accept
    );
    assert_eq!(outbound(&f, PEER, &ipv6_udp("fd00:5::1")), Verdict::Accept);
    let stats = f.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (0, 0));
    assert_eq!(stats.passed_to_acl, 5, "outbound skips the ACL by default");
}

/// `node_l3_gate`.
#[test]
fn node_l3_gate() {
    let f = filter(&node_gate(false, Vec::new())).with_acl(accept_acl());
    for (name, key, packet, accepted) in [
        (
            "no grant",
            PEER,
            tcp(REMOTE, LOCAL, 40_000, 22, 0x02),
            false,
        ),
        (
            "spoofed source",
            PEER,
            tcp(SPOOFED, LOCAL, 40_000, 22, 0x02),
            false,
        ),
        (
            "unbound peer",
            OTHER,
            tcp(REMOTE, LOCAL, 40_000, 22, 0x02),
            false,
        ),
        ("orphan fragment", PEER, orphan_fragment(), false),
        (
            "service vip",
            PEER,
            tcp(REMOTE, SERVICE_VIP, 40_000, 443, 0x02),
            true,
        ),
    ] {
        let verdict = inbound(&f, key, &packet);
        assert_eq!(
            verdict == Verdict::Accept,
            accepted,
            "inbound {name}: {verdict:?}"
        );
    }
    for (name, packet, accepted) in [
        ("no grant", tcp(LOCAL, REMOTE, 40_000, 22, 0x02), false),
        (
            "service vip reply without state",
            tcp(SERVICE_VIP, REMOTE, 443, 40_000, 0x12),
            false,
        ),
        (
            "off-plane",
            tcp(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                40_000,
                443,
                0x02,
            ),
            true,
        ),
    ] {
        let verdict = outbound(&f, PEER, &packet);
        assert_eq!(
            verdict == Verdict::Accept,
            accepted,
            "outbound {name}: {verdict:?}"
        );
    }
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_000, 22, 0x02)),
        dropped(NodeL3Reason::NoGrant.drop_reason())
    );

    let f = filter(&node_gate(true, Vec::new())).with_acl(deny_acl());
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_000, 22, 0x02)),
        Verdict::Accept,
        "same owner opens"
    );
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 22, 40_000, 0x12)),
        Verdict::Accept,
        "same owner reply"
    );
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_001, 22, 0x02)),
        Verdict::Accept,
        "same owner new flow"
    );
}

/// `subnet_lan_dns_transport_and_ingress`, transport part.
#[test]
fn subnet_transport_admission() {
    let port = SUBNET_TRANSPORT_PORT;
    let f = filter(&subnet_publisher())
        .with_acl(deny_acl())
        .with_subnet_transport_port(port);
    assert_eq!(
        inbound(&f, PEER, &udp(REMOTE, LOCAL, 40_000, port)),
        Verdict::Accept,
        "transport request"
    );
    assert!(
        matches!(
            inbound(&f, PEER, &udp(REMOTE, LOCAL, 40_000, port + 1)),
            Verdict::Drop { .. }
        ),
        "other port"
    );
    assert!(
        matches!(
            inbound(&f, OTHER, &udp(REMOTE, LOCAL, 40_000, port)),
            Verdict::Drop { .. }
        ),
        "unbound peer"
    );
    assert_eq!(
        outbound(&f, PEER, &udp(LOCAL, REMOTE, port, 40_000)),
        Verdict::Accept,
        "transport reply"
    );
    let stats = f.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (2, 2));
    assert_eq!(stats.passed_to_acl, 0);

    let f = filter(&subnet_consumer()).with_subnet_transport_port(port);
    assert_eq!(
        outbound(&f, PEER, &udp(LOCAL, REMOTE, 40_000, port)),
        Verdict::Accept,
        "transport request"
    );
    assert!(
        matches!(
            outbound(&f, PEER, &udp(LOCAL, REMOTE, 40_000, port + 1)),
            Verdict::Drop { .. }
        ),
        "other port"
    );
    assert_eq!(
        inbound(&f, PEER, &udp(REMOTE, LOCAL, port, 40_000)),
        Verdict::Accept,
        "transport reply"
    );
}

/// Without the port the reserved transport is an ordinary new flow, which
/// no Grant opens.
#[test]
fn subnet_transport_needs_the_port() {
    let port = SUBNET_TRANSPORT_PORT;
    let f = filter(&subnet_publisher());
    assert!(matches!(
        inbound(&f, PEER, &udp(REMOTE, LOCAL, 40_000, port)),
        Verdict::Drop { .. }
    ));
    let f = filter(&subnet_consumer());
    assert!(matches!(
        outbound(&f, PEER, &udp(LOCAL, REMOTE, 40_000, port)),
        Verdict::Drop { .. }
    ));
}

/// `gateway_consumer_split`.
#[test]
fn gateway_consumer_split() {
    let reply = gateway_reply();
    let queue = Queue::new(1);
    let f = filter(&gateway_gate()).with_divert(queue.clone());
    assert!(
        matches!(inbound(&f, OTHER, &reply), Verdict::Drop { .. }),
        "no consumer authority"
    );
    assert_eq!(
        inbound(&f, GATEWAY, &reply),
        Verdict::Handled,
        "gateway return"
    );
    assert!(
        matches!(inbound(&f, GATEWAY, &reply), Verdict::Drop { .. }),
        "full queue"
    );
    {
        let taken = queue.taken();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, peer_id(GATEWAY));
        assert_eq!(taken[0].1.packet(), reply.as_slice());
    }

    // A closed consumer refuses everything.
    let f = filter(&gateway_gate()).with_divert(|_: PeerId, _: GatewayConsumerPacket| false);
    assert!(
        matches!(inbound(&f, GATEWAY, &reply), Verdict::Drop { .. }),
        "closed queue"
    );

    let f = filter(&gateway_gate());
    assert!(
        matches!(inbound(&f, GATEWAY, &reply), Verdict::Drop { .. }),
        "no consumer channel"
    );
}

/// `peer_keys_are_hot_swappable`.
#[test]
fn peer_keys_are_hot_swappable() {
    let keys = Arc::new(PeerKeyMap::new());
    let f = NodeL3Filter::new(legacy_gate(), Arc::clone(&keys));
    let packet = tcp(REMOTE, SERVICE_VIP, 40_000, 443, 0x02);
    let run = |peer: u32| {
        let mut inbound = PacketBuf::from_packet(&packet);
        let mut outbound = PacketBuf::from_packet(&packet);
        (
            f.inbound(PeerId::new(peer), &mut inbound),
            f.outbound(PeerId::new(peer), &mut outbound),
        )
    };
    let unknown = dropped("node l3: unknown peer");
    assert_eq!(run(1), (unknown, unknown));
    keys.insert(PeerId::new(1), PEER);
    assert_eq!(run(1), (Verdict::Accept, Verdict::Accept));
    assert_eq!(keys.public_key(PeerId::new(1)), Some(PEER));
    keys.replace([(PeerId::new(2), OTHER)]);
    assert_eq!(run(1), (unknown, unknown));
    assert_eq!(run(2), (Verdict::Accept, Verdict::Accept));
    keys.remove(PeerId::new(2));
    assert_eq!(run(2), (unknown, unknown));
    assert_eq!(f.stats().unknown_peer, 6);
}

/// `node_l3_allows_and_denies_with_the_engine_reasons`, with the gate's
/// reasons.
#[test]
fn node_l3_allows_and_denies_with_the_gate_reasons() {
    let allowed = filter(&node_gate(true, Vec::new())).with_acl(accept_acl());
    let ssh = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(inbound(&allowed, PEER, &ssh), Verdict::Accept);
    assert_eq!(
        outbound(&allowed, PEER, &tcp(LOCAL, REMOTE, 40_001, 22, 0x02)),
        Verdict::Accept
    );

    let denied = filter(&node_gate(false, Vec::new())).with_acl(accept_acl());
    assert_eq!(
        inbound(&denied, PEER, &ssh),
        dropped(NodeL3Reason::NoGrant.drop_reason())
    );
    assert_eq!(
        inbound(&denied, PEER, &orphan_fragment()),
        dropped(NodeL3Reason::OrphanFragment.drop_reason()),
        "an orphan fragment"
    );
    assert_eq!(
        outbound(&denied, PEER, &tcp(LOCAL, REMOTE, 40_001, 22, 0x02)),
        dropped(NodeL3Reason::NoGrant.drop_reason())
    );
}

/// `a_denied_gateway_return_is_handled_by_the_gateway_consumer`.
#[test]
fn a_denied_gateway_return_is_handled_by_the_gateway_consumer() {
    let reply = gateway_reply();
    let queue = Queue::new(1);
    let f = filter(&gateway_gate())
        .with_acl(accept_acl())
        .with_divert(queue.clone());
    assert_eq!(inbound(&f, GATEWAY, &reply), Verdict::Handled);
    assert_eq!(queue.taken()[0].1.packet(), reply.as_slice());

    let f = filter(&gateway_gate()).with_acl(accept_acl());
    assert_eq!(
        inbound(&f, GATEWAY, &reply),
        dropped(NodeL3Reason::SourceBinding.drop_reason())
    );
}

// ── Composition ──────────────────────────────────────────────────────────────

#[test]
fn an_enforced_allow_skips_an_acl_that_would_deny() {
    let acl = deny_acl();
    let f = filter(&node_gate(true, Vec::new())).with_acl(acl.clone());
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        Verdict::Accept
    );
    assert_eq!(f.stats().gate_accepted, 1);
    assert_eq!(f.stats().passed_to_acl, 0);
    assert_eq!(acl.stats().denied, 0);
}

#[test]
fn legacy_and_observe_fall_through_to_the_acl() {
    let ssh = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    for (mode, gate) in [("legacy", legacy_gate()), ("observe", observe_gate())] {
        let f = filter(&gate).with_acl(deny_acl());
        assert_eq!(inbound(&f, PEER, &ssh), dropped(reasons::DENIED), "{mode}");
        let f = filter(&gate).with_acl(accept_acl());
        assert_eq!(inbound(&f, PEER, &ssh), Verdict::Accept, "{mode}");
        assert_eq!(f.stats().passed_to_acl, 1, "{mode}");
        let f = filter(&gate);
        assert_eq!(inbound(&f, PEER, &ssh), Verdict::Accept, "{mode}: no ACL");
        let stats = f.stats();
        assert_eq!((stats.gate_accepted, stats.gate_denied), (0, 0), "{mode}");
    }
    let gate = observe_gate();
    let observed = gate.counters().observed_denied;
    let f = filter(&gate).with_acl(accept_acl());
    assert_eq!(inbound(&f, PEER, &ssh), Verdict::Accept);
    assert_eq!(
        gate.counters().observed_denied,
        observed + 1,
        "the gate counts what it would deny"
    );
}

/// Every enforced denial drops with the gate's own reason: a twin gate fed
/// the same packets gives the expected decisions.
#[test]
fn enforced_denials_carry_the_gate_reason() {
    let gate = node_gate(false, Vec::new());
    let twin = node_gate(false, Vec::new());
    let f = filter(&gate).with_acl(accept_acl());
    let inbound_packets = [
        (PEER, tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        (PEER, tcp(SPOOFED, LOCAL, 40_000, 22, 0x02)),
        (OTHER, tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        (PEER, orphan_fragment()),
        (PEER, tcp(REMOTE, LOCAL, 22, 40_000, 0x12)),
    ];
    let mut reasons_seen = Vec::new();
    for (key, packet) in inbound_packets {
        let NodeL3Decision::Enforce {
            allow: false,
            reason,
        } = twin.evaluate_inbound(key, &packet)
        else {
            panic!("the twin gate denies {packet:?}");
        };
        assert_eq!(inbound(&f, key, &packet), dropped(reason.drop_reason()));
        reasons_seen.push(reason);
    }
    assert!(reasons_seen.contains(&NodeL3Reason::NoGrant));
    assert!(reasons_seen.contains(&NodeL3Reason::SourceBinding));
    assert!(reasons_seen.contains(&NodeL3Reason::OrphanFragment));
    for packet in [
        tcp(LOCAL, REMOTE, 40_000, 22, 0x02),
        tcp(SERVICE_VIP, REMOTE, 443, 40_000, 0x12),
    ] {
        let NodeL3Decision::Enforce {
            allow: false,
            reason,
        } = twin.evaluate_outbound(PEER, &packet)
        else {
            panic!("the twin gate denies {packet:?}");
        };
        assert_eq!(outbound(&f, PEER, &packet), dropped(reason.drop_reason()));
    }
    let stats = f.stats();
    assert_eq!((stats.gate_denied, stats.passed_to_acl), (7, 0));
}

#[test]
fn divert_delivers_a_current_candidate() {
    let gate = gateway_gate();
    let queue = Queue::new(4);
    let f = filter(&gate).with_divert(queue.clone());
    let reply = gateway_reply();
    assert_eq!(inbound(&f, GATEWAY, &reply), Verdict::Handled);
    {
        let taken = queue.taken();
        let (peer, candidate) = &taken[0];
        assert_eq!(*peer, peer_id(GATEWAY));
        assert_eq!(candidate.packet(), reply.as_slice());
        assert_eq!(candidate.authority().gateway_id(), "gw-1");
        assert!(gate.gateway_consumer_authority_current(candidate.authority()));
    }
    let stats = f.stats();
    assert_eq!(
        (stats.diverted, stats.divert_rejected, stats.gate_denied),
        (1, 0, 0)
    );
}

#[test]
fn a_full_divert_sink_drops() {
    let f = filter(&gateway_gate()).with_divert(Queue::new(0));
    assert_eq!(
        inbound(&f, GATEWAY, &gateway_reply()),
        dropped(NodeL3Reason::SourceBinding.drop_reason())
    );
    let stats = f.stats();
    assert_eq!(
        (stats.diverted, stats.divert_rejected, stats.gate_denied),
        (0, 1, 1)
    );
}

#[test]
fn without_a_sink_a_gateway_return_drops() {
    let f = filter(&gateway_gate());
    assert_eq!(
        inbound(&f, GATEWAY, &gateway_reply()),
        dropped(NodeL3Reason::SourceBinding.drop_reason())
    );
    let stats = f.stats();
    assert_eq!(
        (stats.diverted, stats.divert_rejected, stats.gate_denied),
        (0, 0, 1)
    );
}

/// Only `SourceBinding` and `OrphanFragment` denials are diverted.
#[test]
fn other_denials_are_never_diverted() {
    let queue = Queue::new(4);
    let f = filter(&node_gate(false, Vec::new())).with_divert(queue.clone());
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        dropped(NodeL3Reason::NoGrant.drop_reason())
    );
    assert!(queue.taken().is_empty());
}

#[test]
fn an_unknown_peer_is_dropped_in_both_directions() {
    let f = NodeL3Filter::new(
        node_gate(true, Vec::new()),
        |_: PeerId| -> Option<[u8; 32]> { None },
    )
    .with_acl(accept_acl());
    let unknown = dropped("node l3: unknown peer");
    assert_eq!(
        inbound(&f, PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        unknown
    );
    assert_eq!(inbound(&f, PEER, &ipv6_udp("fd00:5::1")), unknown);
    assert_eq!(
        outbound(&f, PEER, &tcp(LOCAL, REMOTE, 40_000, 22, 0x02)),
        unknown
    );
    let stats = f.stats();
    assert_eq!((stats.unknown_peer, stats.passed_to_acl), (3, 0));
}

#[test]
fn outbound_acl_runs_only_when_opted_in() {
    let ssh = tcp(LOCAL, REMOTE, 40_000, 22, 0x02);
    let https = tcp(LOCAL, REMOTE, 40_000, 443, 0x02);

    let f = filter(&legacy_gate()).with_acl(outbound_restricted_acl());
    assert_eq!(outbound(&f, PEER, &ssh), Verdict::Accept, "as in ns");
    assert_eq!(f.stats().passed_to_acl, 0);

    let f = filter(&legacy_gate())
        .with_acl(outbound_restricted_acl())
        .with_acl_outbound(true);
    assert_eq!(outbound(&f, PEER, &ssh), dropped(reasons::OUTBOUND));
    assert_eq!(outbound(&f, PEER, &https), Verdict::Accept);
    assert_eq!(f.stats().passed_to_acl, 2);

    // A gate denial ends the decision before the ACL.
    let f = filter(&node_gate(false, Vec::new()))
        .with_acl(outbound_restricted_acl())
        .with_acl_outbound(true);
    assert_eq!(
        outbound(&f, PEER, &ssh),
        dropped(NodeL3Reason::NoGrant.drop_reason())
    );
    assert_eq!(f.stats().passed_to_acl, 0);
    // An enforced allow still meets the opted-in ACL.
    let f = filter(&node_gate(true, Vec::new()))
        .with_acl(outbound_restricted_acl())
        .with_acl_outbound(true);
    assert_eq!(outbound(&f, PEER, &ssh), dropped(reasons::OUTBOUND));
    assert_eq!(f.stats().gate_accepted, 1);
}

#[test]
fn ipv6_skips_the_gate_and_goes_to_the_acl() {
    let gate = node_gate(false, Vec::new());
    let packet = ipv6_udp("fd00:1:2:1:0:7:c0a8:70a");
    let f = filter(&gate).with_acl(deny_acl());
    assert_eq!(inbound(&f, OTHER, &packet), dropped(reasons::DENIED));
    let f = filter(&gate).with_acl(accept_acl());
    assert_eq!(inbound(&f, OTHER, &packet), Verdict::Accept);
    assert_eq!(f.stats().passed_to_acl, 1);
    assert_eq!(inbound(&filter(&gate), OTHER, &packet), Verdict::Accept);
    assert_eq!(outbound(&f, OTHER, &packet), Verdict::Accept);
    let stats = f.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (0, 0));
}

#[test]
fn inbound_from_runs_the_same_steps() {
    let path = Path {
        transport: TransportId::new(0),
        addr: SocketAddr::from(([192, 0, 2, 1], 51_820)),
        ecn: Ecn::NotEct,
    };
    let f = filter(&node_gate(false, Vec::new())).with_acl(deny_acl());
    let mut denied = PacketBuf::from_packet(&tcp(REMOTE, LOCAL, 40_000, 22, 0x02));
    assert_eq!(
        f.inbound_from(peer_id(PEER), &path, &mut denied),
        dropped(NodeL3Reason::NoGrant.drop_reason())
    );
    let mut legacy = PacketBuf::from_packet(&ipv6_udp("fd00:5::1"));
    assert_eq!(
        f.inbound_from(peer_id(PEER), &path, &mut legacy),
        dropped(reasons::DENIED)
    );
    assert_eq!(f.stats().passed_to_acl, 1);
}

#[test]
fn clones_share_state() {
    let f = filter(&node_gate(false, Vec::new()));
    let clone = f.clone();
    assert!(matches!(
        inbound(&clone, PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        Verdict::Drop { .. }
    ));
    assert_eq!(f.stats().gate_denied, 1);
    assert!(Arc::ptr_eq(f.gate(), clone.gate()));
}
