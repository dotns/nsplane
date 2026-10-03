//! Differential replay of ns `NodeL3Runtime` decisions.
//!
//! `../fixtures/differential.json` records operations and their results as
//! produced by ns `tunnel-wg::node_l3::NodeL3Runtime` at ns commit
//! `e98259bc97e5d2053e4d971d76b5099826bf511a` (branch `refactor/nsplane`).
//! Every scenario is replayed here on a fresh [`NodeL3Gate`] with the same
//! target ids, and every step must reproduce the recorded result: the decision
//! kind, verdict and reason of each packet, the gateway consumer candidate,
//! the Subnet transport admission and the `Ok` / error variant of every policy,
//! source and transport operation.
//!
//! The fixture holds 25 scripted scenarios (grants, source binding, reverse
//! and TCP close flows, UDP/ICMP, fragments, malformed packets, modes,
//! generations, source withdrawal, policy markers, gateway delegation, gateway
//! consumer candidates and Subnet transport) and one seeded sequence of 6,000
//! packet steps over a two-Network config with interleaved policy, transport
//! and listener changes. ns has no clock hook and keeps its state limits
//! private, so nothing time-dependent and no state capacity is recorded; both
//! are covered by the ported unit tests.
//!
//! The generator is intentionally not committed. It was a standalone crate
//! (its own `[workspace]`, ns's `Cargo.lock`, the `netlink-packet-core` patch
//! of ns) under a gitignored `.tmp/` of this repository:
//!
//! - `.tmp/ns-ro/`: `git -C <ns> archive refactor/nsplane | tar -x -C .tmp/ns-ro`
//! - `.tmp/md-b-fixture-gen/`: path dependencies on `.tmp/ns-ro/crates/tunnel-wg`,
//!   `control` and `common`, plus `serde_json` and `hex`; a `src/main.rs` that
//!   drives only the public `NodeL3Runtime` API, converts the ns config and
//!   `WgConfig` structs to this crate's JSON shapes, and draws the seeded
//!   sequence from a `SplitMix64` PRNG with a fixed seed.
//!
//! It was run as `cargo run --release -- <ns-commit> > differential.json`;
//! re-running it yields identical bytes.

use std::net::Ipv4Addr;

use serde::Deserialize;

use super::*;

#[derive(Deserialize)]
struct Fixture {
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    targets: Vec<String>,
    steps: Vec<FixtureStep>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FixtureStep {
    Apply {
        source: Option<String>,
        config: NodeL3Config,
        expect: String,
    },
    WithdrawSource {
        source: String,
        expect: String,
    },
    Transport {
        desired: TransportJson,
        installed: Option<TransportJson>,
        expect: String,
    },
    StageTransport {
        config: TransportJson,
        expect: String,
    },
    WithdrawTransport,
    Listeners {
        target: String,
        listeners: Vec<ListenerJson>,
    },
    Inbound {
        peer: String,
        packet: String,
        expect: String,
    },
    Outbound {
        peer: String,
        packet: String,
        expect: String,
    },
    GatewayConsumer {
        peer: String,
        packet: String,
        expect: bool,
    },
    SubnetInbound {
        peer: String,
        packet: String,
        port: u16,
        expect: bool,
    },
    SubnetOutbound {
        peer: String,
        packet: String,
        port: u16,
        expect: bool,
    },
}

#[derive(Deserialize)]
struct TransportJson {
    local_ip: Ipv4Addr,
    peers: Vec<TransportPeerJson>,
}

#[derive(Deserialize)]
struct TransportPeerJson {
    public_key: String,
    allowed_ips: Vec<String>,
    gateway_id: Option<String>,
    relayed: bool,
    node_l3_policy: Option<NodeL3PeerPolicyRequirement>,
}

#[derive(Deserialize)]
struct ListenerJson {
    service_id: String,
    protocol: NodeL3ServiceProtocol,
    port: u16,
}

impl TransportJson {
    fn to_transport(&self) -> NodeL3Transport {
        NodeL3Transport {
            local_ip: self.local_ip,
            peers: self
                .peers
                .iter()
                .map(|peer| NodeL3TransportPeer {
                    public_key: key(&peer.public_key),
                    allowed_ips: peer
                        .allowed_ips
                        .iter()
                        .map(|net| net.parse().unwrap())
                        .collect(),
                    gateway_id: peer.gateway_id.clone(),
                    relayed: peer.relayed,
                    node_l3_policy: peer.node_l3_policy.clone(),
                })
                .collect(),
        }
    }
}

fn bytes(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn key(text: &str) -> [u8; 32] {
    bytes(text).try_into().unwrap()
}

fn decision_text(decision: &NodeL3Decision) -> String {
    let verdict = |allow: bool| if allow { "allow" } else { "deny" };
    match decision {
        NodeL3Decision::Legacy => "legacy".to_owned(),
        NodeL3Decision::Observe {
            would_allow,
            reason,
        } => format!("observe:{}:{}", verdict(*would_allow), reason.as_str()),
        NodeL3Decision::Enforce { allow, reason } => {
            format!("enforce:{}:{}", verdict(*allow), reason.as_str())
        }
    }
}

const fn config_error_name(error: &NodeL3ConfigError) -> &'static str {
    match error {
        NodeL3ConfigError::UnsupportedSchema(_) => "UnsupportedSchema",
        NodeL3ConfigError::WrongTarget { .. } => "WrongTarget",
        NodeL3ConfigError::AuthorityConflict { .. } => "AuthorityConflict",
        NodeL3ConfigError::EmptyField(_) => "EmptyField",
        NodeL3ConfigError::ZeroGeneration => "ZeroGeneration",
        NodeL3ConfigError::StaleGeneration { .. } => "StaleGeneration",
        NodeL3ConfigError::PhaseRegression { .. } => "PhaseRegression",
        NodeL3ConfigError::Conflict(_) => "Conflict",
        NodeL3ConfigError::SnapshotEncoding(_) => "SnapshotEncoding",
        NodeL3ConfigError::UnknownNode(_) => "UnknownNode",
        NodeL3ConfigError::UnknownService(_) => "UnknownService",
        NodeL3ConfigError::ZeroServicePort => "ZeroServicePort",
        NodeL3ConfigError::InvalidSubnetId(_) => "InvalidSubnetId",
        NodeL3ConfigError::InvalidSubnetPrefix(_) => "InvalidSubnetPrefix",
    }
}

const fn transport_error_name(error: &NodeL3TransportError) -> &'static str {
    match error {
        NodeL3TransportError::AmbiguousNodeRoute { .. } => "AmbiguousNodeRoute",
        NodeL3TransportError::InvalidPolicyMarker(_) => "InvalidPolicyMarker",
        NodeL3TransportError::InvalidInstalledProjection(_) => "InvalidInstalledProjection",
    }
}

fn transport_result(result: Result<(), NodeL3TransportError>) -> String {
    result.map_or_else(
        |error| transport_error_name(&error).to_owned(),
        |()| "ok".to_owned(),
    )
}

fn apply_result(gate: &NodeL3Gate, source: Option<&str>, config: &NodeL3Config) -> String {
    source
        .map_or_else(
            || gate.apply(config.clone()),
            |source| gate.apply_from_source(source, config.clone()),
        )
        .map_or_else(|error| config_error_name(&error), |_| "ok")
        .to_owned()
}

fn replace_transport_result(
    gate: &NodeL3Gate,
    desired: &TransportJson,
    installed: Option<&TransportJson>,
) -> String {
    let desired = desired.to_transport();
    transport_result(installed.map_or_else(
        || gate.replace_transport_projection(&desired),
        |installed| {
            gate.replace_transport_projection_after_build(&desired, &installed.to_transport())
        },
    ))
}

/// Run one step; returns `(actual, expected)` for steps with a result.
fn replay(gate: &NodeL3Gate, step: &FixtureStep) -> Option<(String, String)> {
    let outcome = match step {
        FixtureStep::Apply {
            source,
            config,
            expect,
        } => (
            apply_result(gate, source.as_deref(), config),
            expect.clone(),
        ),
        FixtureStep::WithdrawSource { source, expect } => {
            let actual = gate.withdraw_source(source).map_or_else(
                |error| config_error_name(&error).to_owned(),
                |count| format!("ok:{count}"),
            );
            (actual, expect.clone())
        }
        FixtureStep::Transport {
            desired,
            installed,
            expect,
        } => (
            replace_transport_result(gate, desired, installed.as_ref()),
            expect.clone(),
        ),
        FixtureStep::StageTransport { config, expect } => (
            transport_result(gate.stage_transport_projection(&config.to_transport())),
            expect.clone(),
        ),
        FixtureStep::WithdrawTransport => {
            gate.withdraw_transport_projection();
            return None;
        }
        FixtureStep::Listeners { target, listeners } => {
            gate.replace_provider_listeners(
                target,
                listeners.iter().map(|listener| {
                    (
                        listener.service_id.clone(),
                        listener.protocol,
                        listener.port,
                    )
                }),
            );
            return None;
        }
        FixtureStep::Inbound {
            peer,
            packet,
            expect,
        } => (
            decision_text(&gate.evaluate_inbound(key(peer), &bytes(packet))),
            expect.clone(),
        ),
        FixtureStep::Outbound {
            peer,
            packet,
            expect,
        } => (
            decision_text(&gate.evaluate_outbound(key(peer), &bytes(packet))),
            expect.clone(),
        ),
        FixtureStep::GatewayConsumer {
            peer,
            packet,
            expect,
        } => (
            gate.gateway_consumer_packet(key(peer), &bytes(packet))
                .is_some()
                .to_string(),
            expect.to_string(),
        ),
        FixtureStep::SubnetInbound {
            peer,
            packet,
            port,
            expect,
        } => (
            gate.evaluate_subnet_transport_inbound(key(peer), &bytes(packet), *port)
                .to_string(),
            expect.to_string(),
        ),
        FixtureStep::SubnetOutbound {
            peer,
            packet,
            port,
            expect,
        } => (
            gate.evaluate_subnet_transport_outbound(key(peer), &bytes(packet), *port)
                .to_string(),
            expect.to_string(),
        ),
    };
    Some(outcome)
}

#[test]
fn gate_reproduces_the_ns_runtime_differential_fixture() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../fixtures/differential.json")).unwrap();
    let mut packet_steps = 0;
    let mut mismatches = Vec::new();
    for scenario in &fixture.scenarios {
        let gate = NodeL3Gate::new_for_targets(scenario.targets.iter().cloned());
        for (index, step) in scenario.steps.iter().enumerate() {
            if matches!(
                step,
                FixtureStep::Inbound { .. }
                    | FixtureStep::Outbound { .. }
                    | FixtureStep::GatewayConsumer { .. }
                    | FixtureStep::SubnetInbound { .. }
                    | FixtureStep::SubnetOutbound { .. }
            ) {
                packet_steps += 1;
            }
            if let Some((actual, expected)) = replay(&gate, step)
                && actual != expected
            {
                mismatches.push(format!(
                    "{} step {index}: expected {expected}, got {actual}",
                    scenario.name
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches with ns:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(fixture.scenarios.len(), 26);
    assert!(packet_steps >= 6_000, "only {packet_steps} packet steps");
}
