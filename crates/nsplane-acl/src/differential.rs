//! Differential test of the ACL hook: an [`AclFilter`] with its principal
//! cache, flow verdict cache and bypass against the uncached filter (full
//! evaluation of every packet), on generated policies (documents and typed
//! rules with ICMP, other-protocol and label-plus-prefix entries, the policy
//! states), identities (some peers terminating by source address) and packet
//! sequences with policy changes in the middle of flows. The first packet of
//! every new inbound flow is also checked against [`AclEngine::evaluate`].

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{IcmpHeader, IpPacket, PacketBuf, PeerId, protocol};

use crate::engine::{TerminateBinding, wg_peer_anchor};
use crate::filter::{PeerIdentity, assertion_labels};
use crate::matcher::ADDRESS_LABEL;
use crate::test_packets::{Frag, icmp_echo, ip, ip_frag, tcp, udp};
use crate::{
    AclAction, AclEngine, AclFilter, AclFilterConfig, AclFilterStats, AclPolicy, AclRule, Decision,
    Direction, Grant, GrantEnd, IcmpTypes, Label, NamespaceMember, NamespacePolicy, NotInstalled,
    OutboundRule, PeerIdentityMap, PinholeGuard, PinholeSpec, PortSet, Protocol, ProtocolMatch,
    Rule, RuleSet, SourceAssertion, Transport, reasons,
};

/// Peers `1..=PEERS`; peer `PEERS + 1` is never known.
const PEERS: u32 = 6;
const NAMESPACES: [&str; 4] = ["nsd:a", "nsd:b", "quick", "app:s"];
const PORTS: [u16; 5] = [22, 80, 443, 9000, 40000];
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);

/// A 64-bit LCG (Knuth's MMIX constants); the high bits are the output.
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % n
    }

    fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.below(len as u64)).unwrap()
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.index(items.len())]
    }

    /// A known peer.
    fn peer(&mut self) -> u32 {
        1 + u32::try_from(self.below(PEERS.into())).unwrap()
    }
}

fn address(peer: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, u8::try_from(peer).unwrap()))
}

/// Peers 1-4 are key principals, 5 and 6 terminate bindings; `alt` gives the
/// other kind, so an identity change also changes the principal.
fn assertion(peer: u32, alt: bool) -> SourceAssertion {
    if (peer <= 4) == alt {
        SourceAssertion::Terminate {
            binding: TerminateBinding {
                ip: Some(address(peer)),
                anchor: format!("t{peer}"),
            },
        }
    } else {
        SourceAssertion::WgPeerKey {
            pubkey: [u8::try_from(peer).unwrap(); 32],
        }
    }
}

fn principal(peer: u32) -> String {
    assertion(peer, false).source_anchor()
}

/// The principal of a peer, or of an address as a by-source peer resolves it.
fn any_principal(rng: &mut Lcg) -> String {
    let peer = rng.peer();
    if rng.chance(30) {
        address(peer).to_string()
    } else {
        principal(peer)
    }
}

fn rule(src: &str, dst: &str, proto: Option<&str>) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec![src.to_owned()],
        dst: vec![dst.to_owned()],
        proto: proto.map(str::to_owned),
    }
}

fn random_policy(rng: &mut Lcg) -> AclPolicy {
    let pool = [
        rule("*", "*:*", None),
        rule("*", "*:80", Some("tcp")),
        rule("*", "10.0.0.0/24:*", Some("udp")),
        rule("10.0.0.0/24", "*:22", None),
        rule(&wg_peer_anchor(&[2; 32]), "*:443", Some("tcp")),
        rule("10.0.0.3/32", "*:*", Some("tcp")),
        rule("*", "*:*", Some("tcp")),
        rule("*", "*:*", Some("udp")),
    ];
    let acls = (0..rng.below(3)).map(|_| pool[rng.index(pool.len())].clone());
    AclPolicy {
        hosts: HashMap::new(),
        acls: acls.collect(),
        tests: Vec::new(),
    }
}

fn random_rules(rng: &mut Lcg) -> RuleSet {
    let label = |peer| Label::from(principal(peer));
    let net = |s: &str| s.parse().unwrap();
    let pool = [
        Rule::new("any", vec![ProtocolMatch::Any]),
        Rule::new("tcp80", vec![ProtocolMatch::Tcp(PortSet::single(80))]),
        Rule::new("udp-local", vec![ProtocolMatch::Udp(PortSet::Any)])
            .with_destinations([net("10.0.1.0/24")]),
        Rule::new("key2", vec![ProtocolMatch::Tcp(PortSet::list([443, 9000]))])
            .with_labels([label(2)]),
        Rule::new(
            "address",
            vec![ProtocolMatch::Tcp(PortSet::Ranges(vec![
                std::ops::RangeInclusive::new(20, 80),
            ]))],
        )
        .with_labels([Label::from(ADDRESS_LABEL)])
        .with_sources([net("10.0.0.0/29")]),
        Rule::new("t5", vec![ProtocolMatch::Any])
            .with_labels([label(5), label(1)])
            .with_sources([net("10.0.0.5/32")]),
        Rule::new(
            "echo",
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![0, 8]))],
        ),
        Rule::new("icmp-key", vec![ProtocolMatch::Icmp(IcmpTypes::Any)]).with_labels([label(1)]),
        Rule::new("gre", vec![ProtocolMatch::Ip(GRE)]),
        Rule::new(
            "open",
            vec![
                ProtocolMatch::Tcp(PortSet::Any),
                ProtocolMatch::Udp(PortSet::Any),
            ],
        ),
    ];
    let rules = (0..rng.below(3)).map(|_| pool[rng.index(pool.len())].clone());
    RuleSet::new(rules).unwrap()
}

/// Install a random document or typed rule set as the default rules.
fn random_default(rng: &mut Lcg, engine: &AclEngine) {
    if rng.chance(50) {
        let _ = engine.load(random_policy(rng));
    } else {
        engine.install(random_rules(rng));
    }
}

/// An IP protocol other than TCP, UDP and ICMP.
const GRE: u8 = 47;

fn random_namespace(rng: &mut Lcg, app: bool) -> NamespacePolicy {
    let mut members = Vec::new();
    for peer in 1..=PEERS {
        if rng.chance(50) {
            continue;
        }
        let mut addresses = Vec::new();
        if rng.chance(80) {
            addresses.push(address(peer).to_string().parse().unwrap());
        }
        if peer == 4 && rng.chance(30) {
            addresses.push("10.0.2.0/24".parse().unwrap());
        }
        members.push(NamespaceMember {
            principal: principal(peer),
            addresses,
        });
        // The address principal of a by-source peer.
        if rng.chance(30) {
            members.push(NamespaceMember {
                principal: address(peer).to_string(),
                addresses: Vec::new(),
            });
        }
    }
    if app {
        return NamespacePolicy {
            members,
            ..NamespacePolicy::default()
        };
    }
    let outbound = match rng.below(4) {
        0 => Some(vec![OutboundRule {
            proto: Some("tcp".to_owned()),
            ports: "80".to_owned(),
        }]),
        1 => Some(Vec::new()),
        _ => None,
    };
    NamespacePolicy {
        members,
        policy: random_policy(rng),
        outbound,
        allow_app_pinholes: if rng.chance(50) {
            BTreeSet::from(["t".to_owned()])
        } else {
            BTreeSet::new()
        },
    }
}

fn random_end(rng: &mut Lcg) -> GrantEnd {
    if rng.chance(50) {
        GrantEnd::Peer(any_principal(rng))
    } else {
        GrantEnd::Namespace(rng.pick(&NAMESPACES[..3]).into())
    }
}

/// The policy, identity and clock under test, and the open pinholes.
struct World {
    engine: Arc<AclEngine>,
    identity: Arc<PeerIdentityMap>,
    clock: Arc<AtomicU64>,
    guards: Vec<PinholeGuard>,
}

impl World {
    fn new(not_installed: NotInstalled) -> Self {
        let clock = Arc::new(AtomicU64::new(0));
        let base = Instant::now();
        let ticks = Arc::clone(&clock);
        let engine = Arc::new(
            AclEngine::with_clock(move || {
                base + Duration::from_secs(ticks.load(Ordering::Relaxed))
            })
            .with_not_installed(not_installed),
        );
        let identity = Arc::new(PeerIdentityMap::new());
        for peer in 1..PEERS {
            identity.insert(PeerId::new(peer), assertion(peer, false));
        }
        identity.insert_by_source(PeerId::new(PEERS));
        Self {
            engine,
            identity,
            clock,
            guards: Vec::new(),
        }
    }

    fn now(&self) -> Instant {
        self.engine.now()
    }

    /// One random policy, identity or clock change.
    fn change(&mut self, rng: &mut Lcg) {
        match rng.below(14) {
            0 | 1 => random_default(rng, &self.engine),
            2 if rng.chance(50) => self.engine.uninstall(),
            2 => self.engine.fail(),
            3..=5 => {
                let id = rng.pick(&NAMESPACES);
                let namespace = random_namespace(rng, id.starts_with("app:"));
                assert!(self.engine.store_namespace(id, namespace).is_ok());
            }
            6 => {
                self.engine.remove_namespace(rng.pick(&NAMESPACES));
            }
            7 => {
                let grant = Grant {
                    from: random_end(rng),
                    to: random_end(rng),
                    proto: rng
                        .pick(&[None, Some("tcp"), Some("udp")])
                        .map(str::to_owned),
                    ports: rng
                        .pick(&[None, Some("80"), Some("443")])
                        .map(str::to_owned),
                };
                let id = rng.pick(&["g0", "g1"]);
                let _ = self.engine.store_grant(id, grant);
            }
            8 => {
                self.engine.remove_grant(rng.pick(&["g0", "g1"]));
            }
            9 | 12 | 13 => {
                let spec = PinholeSpec {
                    peer: any_principal(rng),
                    kind: "t".to_owned(),
                    protocol: rng.pick(&[Protocol::Tcp, Protocol::Udp]),
                    direction: rng.pick(&[Direction::Inbound, Direction::Outbound]),
                    dst_port: rng.pick(&[80, 9000]),
                    expires_at: self.now() + Duration::from_secs(1 + rng.below(4)),
                };
                if let Ok(guard) = self.engine.open_pinhole("app:s", spec) {
                    self.guards.push(guard);
                }
            }
            10 => {
                if !self.guards.is_empty() {
                    let guard = self.guards.swap_remove(rng.index(self.guards.len()));
                    drop(guard);
                }
            }
            _ => {
                let peer = rng.peer();
                match rng.below(5) {
                    0 => self.identity.remove(PeerId::new(peer)),
                    4 => self.identity.insert_by_source(PeerId::new(peer)),
                    1 => self
                        .identity
                        .insert(PeerId::new(peer), assertion(peer, true)),
                    2 => self.engine.clear_all(),
                    _ => self
                        .identity
                        .insert(PeerId::new(peer), assertion(peer, false)),
                }
            }
        }
    }
}

/// A flow seen from the local node: the remote peer, the direction and the
/// tuple of the packet.
#[derive(Clone, Copy)]
struct Flow {
    peer: u32,
    outbound: bool,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    protocol: u8,
}

impl Flow {
    fn random(rng: &mut Lcg) -> Self {
        let peer = 1 + u32::try_from(rng.below(u64::from(PEERS) + 1)).unwrap();
        // Mostly the peer's own address; a by-source peer's principal
        // follows it.
        let remote = if rng.chance(30) {
            address(rng.peer())
        } else {
            address(peer)
        };
        let other = |rng: &mut Lcg| {
            let member = address(rng.peer());
            rng.pick(&[
                IpAddr::V4(LOCAL),
                IpAddr::V4(LOCAL),
                member,
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 9)),
            ])
        };
        let outbound = rng.chance(40);
        let (src, dst) = if outbound {
            (other(rng), remote)
        } else {
            (remote, other(rng))
        };
        Self {
            peer,
            outbound,
            src,
            src_port: rng.pick(&PORTS),
            dst,
            dst_port: rng.pick(&PORTS),
            protocol: rng.pick(&[
                protocol::TCP,
                protocol::TCP,
                protocol::UDP,
                protocol::UDP,
                protocol::ICMP,
                GRE,
            ]),
        }
    }

    /// The reply: the other direction, addresses and ports swapped.
    const fn reply(self) -> Self {
        Self {
            peer: self.peer,
            outbound: !self.outbound,
            src: self.dst,
            src_port: self.dst_port,
            dst: self.src,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    fn packet(self, rng: &mut Lcg) -> PacketBuf {
        let transport = match self.protocol {
            protocol::TCP => tcp(self.src_port, self.dst_port, b"x"),
            protocol::UDP => udp(self.src_port, self.dst_port, b"x"),
            GRE => vec![0; 8],
            // The reply of an echo request is an echo reply.
            _ => icmp_echo(if self.outbound { 8 } else { 0 }, self.src_port),
        };
        match rng.below(40) {
            0 => PacketBuf::from_packet(&[0x45, 0, 0]),
            1 => ip(self.src, self.dst, self.protocol, &transport[..4]),
            2 | 3 => {
                let frag = Frag {
                    id: 7,
                    offset_units: if rng.chance(50) { 0 } else { 2 },
                    more: rng.chance(50),
                };
                ip_frag(self.src, self.dst, self.protocol, &transport, Some(frag))
            }
            _ => ip(self.src, self.dst, self.protocol, &transport),
        }
    }
}

/// The counters that must match (the verdict cache's own are left out).
const fn comparable(stats: AclFilterStats) -> AclFilterStats {
    AclFilterStats {
        verdict_evictions: 0,
        ..stats
    }
}

/// The counter of the drop reason `reason`.
fn counter(stats: &AclFilterStats, reason: &str) -> u64 {
    match reason {
        reasons::DENIED => stats.denied,
        reasons::NO_POLICY => stats.no_policy,
        reasons::POLICY_FAILED => stats.policy_failed,
        reasons::CROSS_NAMESPACE => stats.cross_namespace,
        reasons::PROTOCOL => stats.protocol,
        other => panic!("unexpected reason {other}"),
    }
}

/// The decision of [`AclEngine::evaluate`] for the inbound `packet` of a known
/// peer when the filter evaluates it as a new flow (well formed, not a later
/// fragment), with the filter's verdict for it.
fn evaluated(world: &World, flow: &Flow, packet: &PacketBuf) -> Option<(Decision, Verdict)> {
    let ip = IpPacket::parse(packet.as_packet()).ok()?;
    if ip.fragment().is_some_and(|f| !f.is_first()) {
        return None;
    }
    let tuple = ip.five_tuple()?;
    let assertion = world
        .identity
        .assertion_for(PeerId::new(flow.peer), tuple.src)?;
    // An IP-bearing assertion's rules see its address as the source.
    let src = assertion.ip().unwrap_or(tuple.src);
    let (src_port, dst_port) = (tuple.src_port, tuple.dst_port);
    let transport = match tuple.protocol {
        protocol::TCP => Transport::Tcp { src_port, dst_port },
        protocol::UDP => Transport::Udp { src_port, dst_port },
        protocol::ICMP => Transport::Icmp {
            icmp_type: IcmpHeader::parse(ip.payload()).ok()?.0.icmp_type(),
        },
        number => Transport::Ip(number),
    };
    let flow = crate::Flow {
        src,
        dst: tuple.dst,
        transport,
    };
    let loaded = world.engine.is_loaded();
    let decision = world.engine.evaluate(&assertion_labels(&assertion), &flow);
    let verdict = match &decision {
        Decision::Accept(_) => Verdict::Accept,
        // Nothing loaded: every inbound packet gets the state's reason.
        Decision::Deny(reason) if !loaded => Verdict::Drop { reason },
        Decision::Deny(_)
            if !matches!(transport, Transport::Tcp { .. } | Transport::Udp { .. }) =>
        {
            Verdict::Drop {
                reason: reasons::PROTOCOL,
            }
        }
        Decision::Deny(reason) => Verdict::Drop { reason },
    };
    Some((decision, verdict))
}

/// Run `steps` random steps with `seed`: both filters must give the same
/// verdict for every packet and end with the same counters, and the first
/// packet of a new inbound flow must get the verdict of
/// [`AclEngine::evaluate`].
fn run(seed: u64, steps: usize, config: AclFilterConfig) {
    let mut rng = Lcg(seed);
    let not_installed = if seed.is_multiple_of(4) {
        NotInstalled::Accept
    } else {
        NotInstalled::Deny
    };
    let mut world = World::new(not_installed);
    let cached = AclFilter::with_config(
        Arc::clone(&world.engine),
        Arc::clone(&world.identity),
        config,
    );
    let reference = AclFilter::uncached(
        Arc::clone(&world.engine),
        Arc::clone(&world.identity),
        config,
    );
    random_default(&mut rng, &world.engine);
    for id in NAMESPACES {
        let namespace = random_namespace(&mut rng, id.starts_with("app:"));
        assert!(world.engine.store_namespace(id, namespace).is_ok());
    }
    for _ in 0..rng.below(6) {
        world.change(&mut rng);
    }
    let mut flows: Vec<Flow> = Vec::new();
    let mut evaluations = 0;
    for step in 0..steps {
        if rng.chance(3) {
            // Time passes: pinholes expire without a generation change.
            world.clock.fetch_add(1, Ordering::Relaxed);
        }
        if rng.chance(5) {
            world.change(&mut rng);
            continue;
        }
        let flow = match (flows.is_empty(), rng.below(10)) {
            (false, 0..=4) => flows[rng.index(flows.len())],
            (false, 5..=7) => flows[rng.index(flows.len())].reply(),
            _ => {
                let flow = Flow::random(&mut rng);
                if flows.len() == 16 {
                    flows.swap_remove(rng.index(16));
                }
                flows.push(flow);
                flow
            }
        };
        let packet = flow.packet(&mut rng);
        let peer = PeerId::new(flow.peer);
        // `allow_other_protocols` takes other protocols before the rules.
        let tcp_udp = matches!(flow.protocol, protocol::TCP | protocol::UDP);
        let expected = (!flow.outbound && (tcp_udp || !config.allow_other_protocols))
            .then(|| evaluated(&world, &flow, &packet))
            .flatten();
        let before = reference.stats();
        let verdicts: [Verdict; 2] = [&cached, &reference].map(|filter| {
            let mut packet = packet.clone();
            if flow.outbound {
                filter.outbound(peer, &mut packet)
            } else {
                filter.inbound(peer, &mut packet)
            }
        });
        assert_eq!(
            verdicts[0],
            verdicts[1],
            "seed {seed} step {step}: cached vs full evaluation (outbound {}, peer {}, generation {})",
            flow.outbound,
            flow.peer,
            world.engine.generation()
        );
        let after = reference.stats();
        // A reply allowance takes the packet before the evaluation.
        if let Some((decision, verdict)) = expected.filter(|_| after.replies == before.replies) {
            assert_eq!(
                verdicts[1], verdict,
                "seed {seed} step {step}: filter vs evaluate {decision:?} (peer {})",
                flow.peer
            );
            let bumped = match verdict {
                Verdict::Drop { reason } => counter(&after, reason) - counter(&before, reason),
                _ => after.accepted - before.accepted,
            };
            assert_eq!(bumped, 1, "seed {seed} step {step}: counter of {verdict:?}");
            evaluations += 1;
        }
    }
    assert!(evaluations > 0, "seed {seed}: no evaluation compared");
    assert_eq!(
        comparable(cached.stats()),
        comparable(reference.stats()),
        "seed {seed}: counters"
    );
}

#[test]
fn cached_verdicts_match_full_evaluation() {
    for seed in 0..200 {
        run(seed, 400, AclFilterConfig::default());
    }
}

#[test]
fn cached_verdicts_match_under_eviction() {
    let config = AclFilterConfig {
        reply_capacity: 3,
        fragment_capacity: 2,
        ..AclFilterConfig::default()
    };
    for seed in 1000..1600 {
        run(seed, 400, config);
    }
}

#[test]
fn cached_verdicts_match_other_configs() {
    let other_protocols = AclFilterConfig {
        allow_other_protocols: true,
        ..AclFilterConfig::default()
    };
    let stateless = AclFilterConfig {
        stateful_replies: false,
        ..AclFilterConfig::default()
    };
    for seed in 2000..2100 {
        run(seed, 400, other_protocols);
        run(seed, 400, stateless);
    }
}
