//! Node L3 gate tests, ported from ns `tunnel-wg/src/node_l3/tests`, plus the
//! state, epoch and concurrency tests of this implementation.

use super::*;
use std::net::{Ipv6Addr, SocketAddrV4};

const LOCAL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const SERVICE_VIP: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 10);
const PEER: [u8; 32] = [7; 32];

fn config(mode: NodeL3Mode, same_owner: bool) -> NodeL3Config {
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
        grants: Vec::new(),
    }
}

fn wg_projection(requirement: Option<(u64, NodeL3Mode)>) -> NodeL3Transport {
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
            node_l3_policy: requirement.map(|(generation, mode)| NodeL3PeerPolicyRequirement {
                network_id: "network-1".to_owned(),
                generation,
                mode,
                node_ips: vec![REMOTE],
            }),
        }],
    }
}

fn gateway_projection(gateway_id: Option<&str>) -> NodeL3Transport {
    NodeL3Transport {
        local_ip: LOCAL,
        peers: vec![NodeL3TransportPeer {
            public_key: [9; 32],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            gateway_id: gateway_id.map(str::to_owned),
            relayed: false,
            node_l3_policy: None,
        }],
    }
}

/// An installed device with no peers.
fn empty_projection() -> NodeL3Transport {
    NodeL3Transport {
        local_ip: LOCAL,
        peers: vec![],
    }
}

fn tcp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut packet = vec![0_u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet
}

fn udp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

fn icmp_error(src: Ipv4Addr, dst: Ipv4Addr, quoted: &[u8]) -> Vec<u8> {
    let quoted_len = quoted.len().min(28);
    let total = 28 + quoted_len;
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    packet[9] = 1;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20] = 3;
    packet[28..].copy_from_slice(&quoted[..quoted_len]);
    packet
}

fn first_fragment(mut packet: Vec<u8>, id: u16) -> Vec<u8> {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let fragment_payload_len = packet.len() - ihl;
    let padding = (8 - fragment_payload_len % 8) % 8;
    packet.resize(packet.len() + padding, 0);
    let total_len = u16::try_from(packet.len()).expect("test IPv4 packet length fits u16");
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    packet
}

fn later_fragment_for_protocol(src: Ipv4Addr, dst: Ipv4Addr, id: u16, protocol: u8) -> Vec<u8> {
    let mut packet = vec![0_u8; 24];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet
}

fn later_fragment(src: Ipv4Addr, dst: Ipv4Addr, id: u16) -> Vec<u8> {
    later_fragment_for_protocol(src, dst, id, 17)
}

/// Check every shard against the gate's counters and limits; returns the
/// flow and fragment entry counts.
fn audit(gate: &NodeL3Gate) -> (usize, usize) {
    let shards = gate.state.lock_all();
    let counts = &gate.state.counts;
    let (mut flows, mut fragments) = (0, 0);
    for (index, shard) in shards.iter().enumerate() {
        let mut per_peer = HashMap::<[u8; 32], usize>::new();
        for key in shard.flows.keys() {
            assert_eq!(state::shard_index(&key.remote_peer), index);
            *per_peer.entry(key.remote_peer).or_default() += 1;
        }
        for key in shard.fragments.keys() {
            assert_eq!(state::shard_index(&key.remote_peer), index);
        }
        assert_eq!(
            per_peer, shard.peer_flows,
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

mod grants_flow;
mod packets_fragments;
mod subnet;
mod transport_policy;

mod gateway_consumer;

mod concurrency;
mod differential;
mod state_table;
