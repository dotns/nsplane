//! Flow gate tests: scopes, bindings, grants, holds and unbound rules, the
//! state table, migration across `replace`, concurrency, the filter, and a
//! model test against a reference implementation.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::time::Duration;

use super::*;
use crate::net::IpNet;
use crate::pinhole::Direction;
use crate::rules::{IcmpTypes, Label, LabelSet, PortSet, ProtocolMatch};

const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const PEER: PeerId = PeerId::new(7);
const OTHER_PEER: PeerId = PeerId::new(8);
const CARRIER: PeerId = PeerId::new(9);

/// The default timeouts.
fn timeouts() -> GateTimeouts {
    GateTimeouts::default()
}

fn host(ip: Ipv4Addr) -> IpNet {
    format!("{ip}/32").parse().unwrap()
}

fn labels(labels: &[&str]) -> LabelSet {
    LabelSet::new(labels.iter().map(|label| Label::from(*label)))
}

fn grant(
    id: &str,
    direction: Direction,
    labels: &[&str],
    destinations: Vec<IpNet>,
    protocols: Vec<ProtocolMatch>,
) -> GateGrant {
    GateGrant {
        id: id.into(),
        direction,
        labels: labels.iter().map(|label| Label::from(*label)).collect(),
        destinations,
        protocols,
        suspended: false,
    }
}

/// An inbound grant for `label` to [`LOCAL`] of every protocol.
fn inbound_any(id: &str, label: &str) -> GateGrant {
    grant(
        id,
        Direction::Inbound,
        &[label],
        vec![host(LOCAL)],
        vec![ProtocolMatch::Any],
    )
}

/// An outbound grant for `label` to [`REMOTE`] of every protocol.
fn outbound_any(id: &str, label: &str) -> GateGrant {
    grant(
        id,
        Direction::Outbound,
        &[label],
        vec![host(REMOTE)],
        vec![ProtocolMatch::Any],
    )
}

fn tcp_port(port: u16) -> ProtocolMatch {
    ProtocolMatch::Tcp(PortSet::single(port))
}

fn binding(peer: PeerId, ip: Ipv4Addr, with: &[&str]) -> GateBinding {
    GateBinding {
        peer,
        addresses: vec![IpAddr::V4(ip)],
        labels: labels(with),
    }
}

/// Scope `id` governing [`LOCAL`], binding [`PEER`] at [`REMOTE`] with the
/// label `remote`, with `grants`.
fn scope(id: &str, mode: GateMode, grants: Vec<GateGrant>) -> GateScope {
    GateScope {
        id: id.into(),
        mode,
        local: vec![IpAddr::V4(LOCAL)],
        bindings: vec![binding(PEER, REMOTE, &["remote"])],
        unbound_addresses: Vec::new(),
        grants,
        unbound: Vec::new(),
    }
}

/// A scope granting `remote` every protocol in both directions.
fn open_scope(mode: GateMode) -> GateScope {
    scope(
        "scope-1",
        mode,
        vec![inbound_any("in", "remote"), outbound_any("out", "remote")],
    )
}

fn policy(scopes: Vec<GateScope>) -> GatePolicy {
    GatePolicy {
        scopes,
        holds: GateHolds::default(),
    }
}

fn gate_with(policy: GatePolicy) -> Arc<FlowGate> {
    let gate = FlowGate::new(GateConfig::default());
    gate.replace(policy).expect("the policy is valid");
    gate
}

fn limited(flows: usize, flows_per_peer: usize, fragments: usize) -> Arc<FlowGate> {
    FlowGate::new(GateConfig {
        limits: GateLimits {
            flows,
            flows_per_peer,
            fragments,
        },
        ..GateConfig::default()
    })
}

fn enforce(allow: bool, reason: GateReason, rule: Option<&str>) -> GateDecision {
    GateDecision::Enforce {
        allow,
        reason,
        rule: rule.map(RuleId::from),
    }
}

fn observe(allow: bool, reason: GateReason, rule: Option<&str>) -> GateDecision {
    GateDecision::Observe {
        allow,
        reason,
        rule: rule.map(RuleId::from),
    }
}

/// An enforced allow by grant `rule`.
fn granted(rule: &str) -> GateDecision {
    enforce(true, GateReason::Granted, Some(rule))
}

fn valid() -> GateDecision {
    enforce(true, GateReason::ValidState, None)
}

fn denied(reason: GateReason) -> GateDecision {
    enforce(false, reason, None)
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

fn icmp(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8, identifier: u16) -> Vec<u8> {
    let mut header = [0_u8; 8];
    header[0] = icmp_type;
    header[4..6].copy_from_slice(&identifier.to_be_bytes());
    ipv4(src, dst, 1, &header)
}

/// A destination-unreachable error from `src` to `dst` quoting `quoted`.
fn icmp_error(src: Ipv4Addr, dst: Ipv4Addr, quoted: &[u8]) -> Vec<u8> {
    let mut payload = vec![3_u8, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&quoted[..quoted.len().min(28)]);
    ipv4(src, dst, 1, &payload)
}

/// Set the fragment id and offset (in 8-byte units) and the more-fragments
/// flag.
fn fragment(mut packet: Vec<u8>, id: u16, offset: u16, more: bool) -> Vec<u8> {
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = if more { 0x2000 } else { 0 };
    packet[6..8].copy_from_slice(&(flags | offset).to_be_bytes());
    packet
}

fn first_fragment(packet: Vec<u8>, id: u16) -> Vec<u8> {
    fragment(packet, id, 0, true)
}

fn later_fragment(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, id: u16) -> Vec<u8> {
    fragment(ipv4(src, dst, protocol, &[0; 8]), id, 1, false)
}

/// Check every shard against the gate's counters and limits; returns the
/// flow and fragment entry counts.
fn audit(gate: &FlowGate) -> (usize, usize) {
    let shards = gate.state.lock_all();
    let counts = &gate.state.counts;
    let (mut flows, mut fragments) = (0, 0);
    for (index, shard) in shards.iter().enumerate() {
        let mut per_peer = HashMap::<PeerId, usize>::new();
        for key in shard.flows.keys() {
            assert_eq!(state::shard_index(key.peer), index);
            *per_peer.entry(key.peer).or_default() += 1;
        }
        for key in shard.fragments.keys() {
            assert_eq!(state::shard_index(key.peer), index);
        }
        assert_eq!(
            per_peer,
            shard.peer_flows.clone().into_iter().collect(),
            "per-peer counts of shard {index}"
        );
        assert!(per_peer.values().all(|count| *count <= counts.peer_limit));
        flows += shard.flows.len();
        fragments += shard.fragments.len();
    }
    assert_eq!(flows, counts.flows.load(Ordering::SeqCst));
    assert_eq!(fragments, counts.fragments.load(Ordering::SeqCst));
    assert!(flows <= counts.global_limit);
    assert!(fragments <= counts.fragment_limit);
    (flows, fragments)
}

// ── IPv6 ──────────────────────────────────────────────────────────────────────

const LOCAL6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const REMOTE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

fn host6(ip: Ipv6Addr) -> IpNet {
    format!("{ip}/128").parse().unwrap()
}

fn binding6(peer: PeerId, ip: Ipv6Addr, with: &[&str]) -> GateBinding {
    GateBinding {
        peer,
        addresses: vec![IpAddr::V6(ip)],
        labels: labels(with),
    }
}

/// [`scope`] over IPv6: governing [`LOCAL6`], binding [`PEER`] at
/// [`REMOTE6`] with the label `remote`.
fn scope6(id: &str, mode: GateMode, grants: Vec<GateGrant>) -> GateScope {
    GateScope {
        local: vec![IpAddr::V6(LOCAL6)],
        bindings: vec![binding6(PEER, REMOTE6, &["remote"])],
        ..scope(id, mode, grants)
    }
}

/// [`open_scope`] over IPv6: `remote` may open every protocol to
/// [`LOCAL6`] inbound and to [`REMOTE6`] outbound.
fn open_scope6(mode: GateMode) -> GateScope {
    scope6(
        "scope-1",
        mode,
        vec![
            grant(
                "in",
                Direction::Inbound,
                &["remote"],
                vec![host6(LOCAL6)],
                vec![ProtocolMatch::Any],
            ),
            grant(
                "out",
                Direction::Outbound,
                &["remote"],
                vec![host6(REMOTE6)],
                vec![ProtocolMatch::Any],
            ),
        ],
    )
}

/// An IPv6 extension header of `kind` and its bytes; the first byte (the
/// next header) is filled in by [`ipv6_with`].
type Extension = (u8, Vec<u8>);

/// A Hop-by-Hop (0), Routing (43) or Destination Options (60) header of
/// `units` 8-byte units.
fn options(kind: u8, units: u8) -> Extension {
    let mut header = vec![0_u8; usize::from(units) * 8];
    header[1] = units - 1;
    (kind, header)
}

/// An Authentication Header of 16 bytes (its length counts 4-byte units).
fn ah() -> Extension {
    let mut header = vec![0_u8; 16];
    header[1] = 2;
    (51, header)
}

/// A Fragment header: identification, offset in 8-byte units and the
/// more-fragments flag.
fn fragment6(id: u32, offset: u16, more: bool) -> Extension {
    let mut header = vec![0_u8; 8];
    header[2..4].copy_from_slice(&((offset << 3) | u16::from(more)).to_be_bytes());
    header[4..8].copy_from_slice(&id.to_be_bytes());
    (44, header)
}

/// An IPv6 packet whose `extensions` precede the upper layer `protocol`
/// carrying `payload`.
fn ipv6_with(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    extensions: &[Extension],
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let kinds: Vec<u8> = extensions
        .iter()
        .map(|(kind, _)| *kind)
        .chain([protocol])
        .collect();
    let mut packet = vec![0_u8; 40];
    packet[0] = 0x60;
    packet[6] = kinds[0];
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    for (index, (_, header)) in extensions.iter().enumerate() {
        let start = packet.len();
        packet.extend_from_slice(header);
        packet[start] = kinds[index + 1];
    }
    packet.extend_from_slice(payload);
    let length = u16::try_from(packet.len() - 40).unwrap();
    packet[4..6].copy_from_slice(&length.to_be_bytes());
    packet
}

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    ipv6_with(src, dst, &[], protocol, payload)
}

fn tcp_header(src_port: u16, dst_port: u16, flags: u8) -> [u8; 20] {
    let mut header = [0_u8; 20];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[12] = 0x50;
    header[13] = flags;
    header
}

fn udp_header(src_port: u16, dst_port: u16) -> [u8; 8] {
    let mut header = [0_u8; 8];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..6].copy_from_slice(&8_u16.to_be_bytes());
    header
}

fn icmp_header(icmp_type: u8, identifier: u16) -> [u8; 8] {
    let mut header = [0_u8; 8];
    header[0] = icmp_type;
    header[4..6].copy_from_slice(&identifier.to_be_bytes());
    header
}

fn tcp6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    ipv6(src, dst, 6, &tcp_header(src_port, dst_port, flags))
}

fn udp6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    ipv6(src, dst, 17, &udp_header(src_port, dst_port))
}

fn icmp6(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, identifier: u16) -> Vec<u8> {
    ipv6(src, dst, 58, &icmp_header(icmp_type, identifier))
}

/// An `ICMPv6` error of `icmp_type` from `src` to `dst` quoting `quoted`.
fn icmp6_error(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, quoted: &[u8]) -> Vec<u8> {
    let mut payload = vec![icmp_type, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(quoted);
    ipv6(src, dst, 58, &payload)
}

/// A first UDP fragment (offset 0, more fragments) with the id `id`.
fn first_fragment6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, id: u32) -> Vec<u8> {
    ipv6_with(
        src,
        dst,
        &[fragment6(id, 0, true)],
        17,
        &udp_header(src_port, dst_port),
    )
}

fn later_fragment6(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, id: u32) -> Vec<u8> {
    ipv6_with(src, dst, &[fragment6(id, 1, false)], protocol, &[0; 8])
}

/// [`audit`] over both address families: every shard's per-peer counts
/// cover the flows of both; returns the flow and fragment entry counts of
/// both.
fn audit_families(gate: &FlowGate) -> (usize, usize) {
    let shards = gate.state.lock_all();
    let counts = &gate.state.counts;
    let (mut flows, mut fragments) = (0, 0);
    for (index, shard) in shards.iter().enumerate() {
        let mut per_peer = HashMap::<PeerId, usize>::new();
        let peers = shard
            .flows
            .keys()
            .map(|key| key.peer)
            .chain(shard.flows6.keys().map(|key| key.peer));
        for peer in peers {
            assert_eq!(state::shard_index(peer), index);
            *per_peer.entry(peer).or_default() += 1;
        }
        let fragment_peers = shard
            .fragments
            .keys()
            .map(|key| key.peer)
            .chain(shard.fragments6.keys().map(|key| key.peer));
        for peer in fragment_peers {
            assert_eq!(state::shard_index(peer), index);
        }
        assert_eq!(
            per_peer,
            shard.peer_flows.clone().into_iter().collect(),
            "per-peer counts of shard {index}"
        );
        assert!(per_peer.values().all(|count| *count <= counts.peer_limit));
        flows += shard.flows.len() + shard.flows6.len();
        fragments += shard.fragments.len() + shard.fragments6.len();
    }
    assert_eq!(flows, counts.flows.load(Ordering::SeqCst));
    assert_eq!(fragments, counts.fragments.load(Ordering::SeqCst));
    assert!(flows <= counts.global_limit);
    assert!(fragments <= counts.fragment_limit);
    (flows, fragments)
}

mod concurrency;
mod grant_kinds;
mod grants_flow;
mod holds_and_unbound;
mod ipv6_flows;
mod ipv6_packets;
mod model;
mod packets_fragments;
mod peer_keyed;
mod state_table;
