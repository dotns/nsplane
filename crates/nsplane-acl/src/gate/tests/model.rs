//! The gate against a simple reference model of its specification: one
//! flow map, no shards, no slots, no lazy expiry, matching straight on the
//! [`GatePolicy`]. Seeded random sequences of packets, `replace` calls and
//! clock steps must give equal decisions and counters, so the sharded state,
//! its migration and lazy expiry never change a verdict. The sequences run
//! over IPv4, over IPv6, over both families at once, and over both families
//! with peer-keyed bindings.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use super::*;
use crate::rules::Transport;

const SEEDS: u64 = 48;
const STEPS: usize = 400;
const LIMITS: GateLimits = GateLimits {
    flows: 8,
    flows_per_peer: 4,
    fragments: 3,
};

const LOCALS: [Ipv4Addr; 2] = [LOCAL, Ipv4Addr::new(100, 64, 0, 10)];
const REMOTES: [Ipv4Addr; 3] = [
    REMOTE,
    Ipv4Addr::new(100, 64, 0, 3),
    Ipv4Addr::new(100, 127, 0, 1),
];
const LOCALS6: [Ipv6Addr; 2] = [LOCAL6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x10)];
const REMOTES6: [Ipv6Addr; 3] = [
    REMOTE6,
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3),
    Ipv6Addr::new(0xfd7f, 0, 0, 0, 0, 0, 0, 1),
];
const PEERS: [PeerId; 3] = [PEER, OTHER_PEER, CARRIER];
const LABELS: [&str; 2] = ["a", "b"];

/// The address families of a sequence. An IPv4 sequence draws exactly the
/// random numbers it drew before IPv6 was added, so its seeds are the same
/// sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
    /// Policies list every address in both families; each packet picks one.
    Both,
    /// [`Family::Both`], and scopes also bind peers by peer.
    PeerKeyed,
}

impl Family {
    /// The policy entries for address `index` of `v4` and `v6`.
    fn addresses(self, index: usize, v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Vec<IpAddr> {
        match self {
            Self::V4 => vec![IpAddr::V4(v4[index])],
            Self::V6 => vec![IpAddr::V6(v6[index])],
            Self::Both | Self::PeerKeyed => vec![IpAddr::V4(v4[index]), IpAddr::V6(v6[index])],
        }
    }

    fn hosts(self, index: usize, v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Vec<IpNet> {
        self.addresses(index, v4, v6)
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V4(ip) => host(ip),
                IpAddr::V6(ip) => host6(ip),
            })
            .collect()
    }

    /// Whether the next packet is IPv6.
    fn packet_v6(self, rng: &mut Rng) -> bool {
        match self {
            Self::V4 => false,
            Self::V6 => true,
            Self::Both | Self::PeerKeyed => rng.chance(50),
        }
    }
}

/// Address `index` of `v4` or `v6`.
fn address(v6: bool, index: usize, v4_table: &[Ipv4Addr], v6_table: &[Ipv6Addr]) -> IpAddr {
    if v6 {
        IpAddr::V6(v6_table[index])
    } else {
        IpAddr::V4(v4_table[index])
    }
}

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

// ── Policies ──────────────────────────────────────────────────────────────────

fn random_protocols(rng: &mut Rng, family: Family) -> Vec<ProtocolMatch> {
    let echo = match family {
        Family::V4 => vec![8],
        Family::V6 | Family::Both | Family::PeerKeyed => vec![8, 128],
    };
    let choices = [
        ProtocolMatch::Any,
        tcp_port(22),
        ProtocolMatch::Udp(PortSet::single(53)),
        ProtocolMatch::Icmp(IcmpTypes::Only(echo)),
    ];
    let mut protocols = vec![choices[rng.below(choices.len())].clone()];
    if rng.chance(30) {
        protocols.push(choices[rng.below(choices.len())].clone());
    }
    protocols
}

fn random_scope(rng: &mut Rng, index: usize, family: Family) -> GateScope {
    let mode = rng.pick(&[
        GateMode::Off,
        GateMode::Observe,
        GateMode::Enforce,
        GateMode::Enforce,
    ]);
    let mut local = family.addresses(index % 2, &LOCALS, &LOCALS6);
    if rng.chance(25) {
        local.extend(family.addresses((index + 1) % 2, &LOCALS, &LOCALS6));
    }
    let mut bindings = Vec::new();
    // Peers bound by peer, which then have no address-listed binding here.
    let keyed: Vec<PeerId> = if family == Family::PeerKeyed {
        PEERS.iter().copied().filter(|_| rng.chance(30)).collect()
    } else {
        Vec::new()
    };
    for peer in &keyed {
        let with: Vec<&str> = LABELS.iter().copied().filter(|_| rng.chance(60)).collect();
        bindings.push(GateBinding {
            peer: *peer,
            addresses: Vec::new(),
            labels: labels(&with),
        });
    }
    let mut seen = Vec::new();
    for _ in 0..rng.below(4) {
        let pair = (rng.pick(&PEERS), rng.below(2));
        if !seen.contains(&pair) && !keyed.contains(&pair.0) {
            seen.push(pair);
            let with: Vec<&str> = LABELS.iter().copied().filter(|_| rng.chance(60)).collect();
            bindings.push(GateBinding {
                peer: pair.0,
                addresses: family.addresses(pair.1, &REMOTES, &REMOTES6),
                labels: labels(&with),
            });
        }
    }
    let grants = (0..rng.below(4))
        .map(|n| GateGrant {
            id: format!("g{index}-{n}").into(),
            direction: rng.pick(&[Direction::Inbound, Direction::Outbound]),
            labels: LABELS
                .iter()
                .filter(|_| rng.chance(40))
                .map(|label| Label::from(*label))
                .collect(),
            destinations: if rng.chance(40) {
                let all4 = [LOCALS[0], LOCALS[1], REMOTES[0], REMOTES[1]];
                let all6 = [LOCALS6[0], LOCALS6[1], REMOTES6[0], REMOTES6[1]];
                family.hosts(rng.below(all4.len()), &all4, &all6)
            } else {
                Vec::new()
            },
            protocols: random_protocols(rng, family),
            suspended: rng.chance(20),
        })
        .collect();
    let unbound = (0..rng.below(3))
        .map(|n| UnboundRule {
            id: format!("u{index}-{n}").into(),
            peers: PEERS.iter().copied().filter(|_| rng.chance(50)).collect(),
            action: rng.pick(&[UnboundAction::Pass, UnboundAction::Divert]),
            protocols: random_protocols(rng, family),
        })
        .collect();
    // Remote addresses of the scope without a binding: any remote address
    // this scope does not bind (another scope may bind it).
    let unbound_addresses = (0..REMOTES.len())
        .filter(|index| !seen.iter().any(|(_, bound)| bound == index) && rng.chance(25))
        .flat_map(|index| family.addresses(index, &REMOTES, &REMOTES6))
        .collect();
    GateScope {
        id: format!("s{index}").into(),
        mode,
        local,
        bindings,
        unbound_addresses,
        grants,
        unbound,
    }
}

fn random_holds(rng: &mut Rng, family: Family) -> GateHolds {
    let mut holds = GateHolds::default();
    if rng.chance(70) {
        return holds;
    }
    let rule = |rng: &mut Rng| HoldRule {
        peers: rng.chance(30).then(|| vec![rng.pick(&PEERS)]),
        local: if rng.chance(50) {
            family.hosts(rng.below(LOCALS.len()), &LOCALS, &LOCALS6)
        } else {
            Vec::new()
        },
        remote: family.hosts(rng.below(REMOTES.len()), &REMOTES, &REMOTES6),
    };
    if rng.chance(60) {
        holds.inbound.push(rule(rng));
    }
    if rng.chance(40) {
        holds.outbound.push(rule(rng));
    }
    if rng.chance(50) {
        let peer = rng.pick(&PEERS);
        for ip in family.addresses(rng.below(REMOTES.len()), &REMOTES, &REMOTES6) {
            holds.release.push((peer, ip));
        }
    }
    holds
}

/// A new policy, or (mostly) the current one with one scope changed, so
/// that unchanged scopes keep their state.
fn next_policy(rng: &mut Rng, current: &GatePolicy, family: Family) -> GatePolicy {
    if current.scopes.is_empty() || rng.chance(25) {
        let scopes = (0..=rng.below(2))
            .map(|index| random_scope(rng, index, family))
            .collect();
        return GatePolicy {
            scopes,
            holds: random_holds(rng, family),
        };
    }
    let mut next = current.clone();
    match rng.below(5) {
        0 => next.holds = random_holds(rng, family),
        1 => {
            let index = rng.below(next.scopes.len());
            next.scopes[index].mode =
                rng.pick(&[GateMode::Off, GateMode::Observe, GateMode::Enforce]);
        }
        2 => {
            let index = rng.below(next.scopes.len());
            for grant in &mut next.scopes[index].grants {
                if rng.chance(50) {
                    grant.suspended = !grant.suspended;
                }
            }
        }
        3 => {
            let index = rng.below(next.scopes.len());
            let id = next.scopes[index].id.clone();
            next.scopes[index] = GateScope {
                id,
                ..random_scope(rng, index, family)
            };
        }
        _ => {}
    }
    next
}

// ── Packets ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fragment {
    Whole,
    First(u16),
    Later(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp(u8),
    Udp,
    /// Echo request (8, or 128 in IPv6) or reply (0, or 129) with an
    /// identifier.
    Echo(u8, u16),
    /// A destination-unreachable error quoting a UDP packet
    /// `(src, dst, src_port, dst_port)`.
    Error(IpAddr, IpAddr, u16, u16),
    Malformed,
}

/// The echo type of the family: a request (8 or 128) or a reply (0 or 129).
const fn echo(v6: bool, request: bool) -> u8 {
    match (v6, request) {
        (false, true) => 8,
        (false, false) => 0,
        (true, true) => 128,
        (true, false) => 129,
    }
}

#[derive(Debug, Clone, Copy)]
struct Packet {
    src: IpAddr,
    dst: IpAddr,
    kind: Kind,
    src_port: u16,
    dst_port: u16,
    fragment: Fragment,
}

impl Packet {
    const fn v6(&self) -> bool {
        self.src.is_ipv6()
    }

    fn bytes(&self) -> Vec<u8> {
        match (self.src, self.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.bytes_v4(src, dst),
            (IpAddr::V6(src), IpAddr::V6(dst)) => self.bytes_v6(src, dst),
            _ => unreachable!("one family per packet"),
        }
    }

    fn bytes_v6(&self, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let (src_port, dst_port) = (self.src_port, self.dst_port);
        match (self.fragment, self.kind) {
            (_, Kind::Malformed) => {
                let mut packet = tcp6(src, dst, src_port, dst_port, 0x02);
                packet.truncate(50);
                packet[4..6].copy_from_slice(&10_u16.to_be_bytes());
                packet
            }
            (Fragment::First(id), _) => first_fragment6(src, dst, src_port, dst_port, id.into()),
            (Fragment::Later(id), _) => later_fragment6(src, dst, 17, id.into()),
            (_, Kind::Tcp(flags)) => tcp6(src, dst, src_port, dst_port, flags),
            (_, Kind::Udp) => udp6(src, dst, src_port, dst_port),
            (_, Kind::Echo(icmp_type, identifier)) => icmp6(src, dst, icmp_type, identifier),
            (_, Kind::Error(IpAddr::V6(qs), IpAddr::V6(qd), qsp, qdp)) => {
                icmp6_error(src, dst, 1, &udp6(qs, qd, qsp, qdp))
            }
            (_, Kind::Error(..)) => unreachable!("one family per packet"),
        }
    }

    fn bytes_v4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let packet = match self.kind {
            Kind::Tcp(flags) => tcp(src, dst, self.src_port, self.dst_port, flags),
            Kind::Udp => udp(src, dst, self.src_port, self.dst_port),
            Kind::Echo(icmp_type, identifier) => icmp(src, dst, icmp_type, identifier),
            Kind::Error(IpAddr::V4(qs), IpAddr::V4(qd), qsp, qdp) => {
                icmp_error(src, dst, &udp(qs, qd, qsp, qdp))
            }
            Kind::Error(..) => unreachable!("one family per packet"),
            Kind::Malformed => {
                let mut packet = tcp(src, dst, self.src_port, self.dst_port, 0x02);
                packet.truncate(30);
                packet[2..4].copy_from_slice(&30_u16.to_be_bytes());
                return packet;
            }
        };
        match self.fragment {
            Fragment::Whole => packet,
            Fragment::First(id) => first_fragment(packet, id),
            Fragment::Later(id) => later_fragment(src, dst, 17, id),
        }
    }

    /// The transport a grant or rule matches; `None` for a later fragment.
    const fn transport(&self) -> Option<Transport> {
        let (src_port, dst_port) = (self.src_port, self.dst_port);
        match (self.fragment, self.kind) {
            (Fragment::Later(_), _) | (_, Kind::Malformed) => None,
            (_, Kind::Tcp(_)) => Some(Transport::Tcp { src_port, dst_port }),
            (_, Kind::Udp) => Some(Transport::Udp { src_port, dst_port }),
            (_, Kind::Echo(icmp_type, _)) => Some(Transport::Icmp { icmp_type }),
            (_, Kind::Error(..)) => Some(Transport::Icmp {
                icmp_type: if self.v6() { 1 } else { 3 },
            }),
        }
    }

    fn fragment_key(
        &self,
        scope: &GateScope,
        direction: PacketDirection,
        peer: PeerId,
        id: u16,
    ) -> ModelFragmentKey {
        ModelFragmentKey {
            scope: scope.id.clone(),
            direction,
            peer,
            src: self.src,
            dst: self.dst,
            id,
        }
    }

    const fn protocol(&self) -> u8 {
        match self.kind {
            Kind::Tcp(_) | Kind::Malformed => 6,
            Kind::Udp => 17,
            Kind::Echo(..) | Kind::Error(..) if self.v6() => 58,
            Kind::Echo(..) | Kind::Error(..) => 1,
        }
    }
}

fn random_packet(rng: &mut Rng, direction: PacketDirection, family: Family) -> Packet {
    let v6 = family.packet_v6(rng);
    let local = address(v6, rng.below(LOCALS.len()), &LOCALS, &LOCALS6);
    let remote = address(v6, rng.below(REMOTES.len()), &REMOTES, &REMOTES6);
    let (src, dst) = match direction {
        PacketDirection::Inbound => (remote, local),
        PacketDirection::Outbound => (local, remote),
    };
    let ports = [0, 22, 53, 40_000, 40_001];
    let (src_port, dst_port) = (rng.pick(&ports[1..]), rng.pick(&ports));
    let kind = match rng.below(10) {
        0..=3 => Kind::Tcp(rng.pick(&[0x02, 0x02, 0x10, 0x12, 0x11, 0x04])),
        4..=6 => Kind::Udp,
        7 => Kind::Echo(echo(v6, rng.pick(&[false, true])), rng.pick(&[1, 2])),
        8 => {
            // Quote a packet the other way, mostly a plausible one.
            let (qs, qd) = if rng.chance(80) {
                (dst, src)
            } else {
                (
                    dst,
                    address(v6, rng.below(REMOTES.len()), &REMOTES, &REMOTES6),
                )
            };
            Kind::Error(qs, qd, rng.pick(&ports[1..]), rng.pick(&ports[1..]))
        }
        _ => Kind::Malformed,
    };
    let fragment = match (kind, rng.below(10)) {
        (Kind::Udp, 0..=1) => Fragment::First(rng.pick(&[1, 2])),
        (Kind::Udp, 2) => Fragment::Later(rng.pick(&[1, 2])),
        _ => Fragment::Whole,
    };
    Packet {
        src,
        dst,
        kind,
        src_port,
        dst_port,
        fragment,
    }
}

fn fresh(rng: &mut Rng, family: Family) -> (PacketDirection, PeerId, Packet) {
    let direction = rng.pick(&[PacketDirection::Inbound, PacketDirection::Outbound]);
    (
        direction,
        rng.pick(&PEERS),
        random_packet(rng, direction, family),
    )
}

/// A packet related to an allowed one: a reply, a repeat, a later
/// fragment, an ICMP error about it, or a new flow from the same source.
fn follow_up(
    rng: &mut Rng,
    (direction, peer, packet): (PacketDirection, PeerId, Packet),
) -> (PacketDirection, PeerId, Packet) {
    let back = match direction {
        PacketDirection::Inbound => PacketDirection::Outbound,
        PacketDirection::Outbound => PacketDirection::Inbound,
    };
    let reply = Packet {
        src: packet.dst,
        dst: packet.src,
        src_port: packet.dst_port,
        dst_port: packet.src_port,
        kind: match packet.kind {
            Kind::Tcp(_) => Kind::Tcp(rng.pick(&[0x10, 0x12, 0x11, 0x04, 0x02])),
            Kind::Echo(_, identifier) => Kind::Echo(echo(packet.v6(), false), identifier),
            kind => kind,
        },
        fragment: Fragment::Whole,
    };
    match rng.below(6) {
        0 | 1 => (back, peer, reply),
        2 => (
            direction,
            peer,
            Packet {
                kind: match packet.kind {
                    Kind::Tcp(_) => Kind::Tcp(rng.pick(&[0x10, 0x11, 0x04, 0x02])),
                    kind => kind,
                },
                fragment: Fragment::Whole,
                ..packet
            },
        ),
        3 => match packet.fragment {
            Fragment::First(id) => (
                direction,
                peer,
                Packet {
                    fragment: Fragment::Later(id),
                    ..packet
                },
            ),
            _ => (
                direction,
                peer,
                Packet {
                    fragment: Fragment::First(rng.pick(&[1, 2])),
                    kind: Kind::Udp,
                    ..packet
                },
            ),
        },
        4 => (
            back,
            peer,
            Packet {
                kind: Kind::Error(packet.src, packet.dst, packet.src_port, packet.dst_port),
                fragment: Fragment::Whole,
                ..reply
            },
        ),
        _ => (
            direction,
            rng.pick(&PEERS),
            Packet {
                src_port: rng.pick(&[40_002, 40_003, 40_004]),
                fragment: Fragment::Whole,
                ..packet
            },
        ),
    }
}

// ── The model ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModelFlowKey {
    scope: ScopeId,
    peer: PeerId,
    remote: IpAddr,
    local: IpAddr,
    protocol: u8,
    remote_port: u16,
    local_port: u16,
}

#[derive(Debug, Clone)]
struct ModelFlow {
    initiator: PacketDirection,
    opened: Transport,
    rule: RuleId,
    enforced: bool,
    close: Close,
    expires: Instant,
}

/// FIN and RST progress of a TCP flow.
#[derive(Debug, Clone, Copy, Default)]
struct Close {
    fin_initiator: bool,
    fin_responder: bool,
    reset: bool,
}

impl Close {
    const fn closing(self) -> bool {
        self.fin_initiator || self.fin_responder || self.reset
    }

    const fn terminal(self) -> bool {
        self.reset || (self.fin_initiator && self.fin_responder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModelFragmentKey {
    scope: ScopeId,
    direction: PacketDirection,
    peer: PeerId,
    src: IpAddr,
    dst: IpAddr,
    id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Allow,
    Pass,
}

#[derive(Default)]
struct Model {
    policy: GatePolicy,
    flows: HashMap<ModelFlowKey, ModelFlow>,
    fragments: HashMap<ModelFragmentKey, (Disposition, Instant)>,
    counters: GateCounters,
}

fn protocol_matches(protocol: &ProtocolMatch, transport: Transport) -> bool {
    match (protocol, transport) {
        (ProtocolMatch::Any, _) | (ProtocolMatch::Icmp(IcmpTypes::Any), Transport::Icmp { .. }) => {
            true
        }
        (ProtocolMatch::Tcp(ports), Transport::Tcp { dst_port, .. })
        | (ProtocolMatch::Udp(ports), Transport::Udp { dst_port, .. }) => ports.contains(dst_port),
        (ProtocolMatch::Icmp(IcmpTypes::Only(types)), Transport::Icmp { icmp_type }) => {
            types.contains(&icmp_type)
        }
        (ProtocolMatch::Ip(number), Transport::Ip(protocol)) => *number == protocol,
        _ => false,
    }
}

fn net_matches(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(&ip))
}

/// The labels of the binding of `peer` at `remote` in `scope`: exact or
/// peer-keyed (a scope never has both for one peer).
fn binding_labels(scope: &GateScope, peer: PeerId, remote: IpAddr) -> Option<&LabelSet> {
    scope
        .bindings
        .iter()
        .find(|binding| {
            binding.peer == peer
                && (binding.addresses.contains(&remote) || binding.addresses.is_empty())
        })
        .map(|binding| &binding.labels)
}

fn binds_exactly(scope: &GateScope, peer: PeerId, remote: IpAddr) -> bool {
    scope
        .bindings
        .iter()
        .any(|binding| binding.peer == peer && binding.addresses.contains(&remote))
}

fn binds_by_peer(scope: &GateScope, peer: PeerId) -> bool {
    scope
        .bindings
        .iter()
        .any(|binding| binding.peer == peer && binding.addresses.is_empty())
}

fn active_scopes(policy: &GatePolicy) -> impl Iterator<Item = &GateScope> {
    policy
        .scopes
        .iter()
        .filter(|scope| scope.mode != GateMode::Off)
}

/// The scopes binding a packet of `peer` between `local` and `remote`: those
/// governing `local` that bind the exact pair, else those governing `local`
/// that bind the peer by peer.
fn binding_level(
    policy: &GatePolicy,
    peer: PeerId,
    remote: IpAddr,
    local: IpAddr,
) -> Vec<&GateScope> {
    let exact: Vec<&GateScope> = active_scopes(policy)
        .filter(|scope| governs(scope, local) && binds_exactly(scope, peer, remote))
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    active_scopes(policy)
        .filter(|scope| governs(scope, local) && binds_by_peer(scope, peer))
        .collect()
}

fn governs(scope: &GateScope, local: IpAddr) -> bool {
    scope.local.contains(&local)
}

fn decision(enforce: bool, allow: bool, reason: GateReason, rule: Option<RuleId>) -> GateDecision {
    mode_decision(enforce, allow, reason, rule)
}

/// The first grant of `scope` admitting a new flow, or a suspended one.
fn authorize(
    scope: &GateScope,
    direction: PacketDirection,
    labels: &LabelSet,
    destination: IpAddr,
    transport: Transport,
) -> Result<RuleId, Option<RuleId>> {
    let mut suspended = None;
    for grant in &scope.grants {
        let grant_direction = match grant.direction {
            Direction::Inbound => PacketDirection::Inbound,
            Direction::Outbound => PacketDirection::Outbound,
        };
        if grant_direction == direction
            && (grant.labels.is_empty() || grant.labels.iter().any(|label| labels.contains(label)))
            && net_matches(&grant.destinations, destination)
            && grant
                .protocols
                .iter()
                .any(|protocol| protocol_matches(protocol, transport))
        {
            if !grant.suspended {
                return Ok(grant.id.clone());
            }
            suspended.get_or_insert_with(|| grant.id.clone());
        }
    }
    Err(suspended)
}

impl Model {
    fn active(&self) -> impl Iterator<Item = &GateScope> {
        active_scopes(&self.policy)
    }

    fn held(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        local: IpAddr,
        remote: IpAddr,
    ) -> bool {
        let holds = &self.policy.holds;
        let rules = match direction {
            PacketDirection::Inbound => {
                if holds.release.contains(&(peer, remote)) {
                    return false;
                }
                &holds.inbound
            }
            PacketDirection::Outbound => &holds.outbound,
        };
        rules.iter().any(|rule| {
            rule.peers
                .as_ref()
                .is_none_or(|peers| peers.contains(&peer))
                && net_matches(&rule.local, local)
                && net_matches(&rule.remote, remote)
        })
    }

    /// Deny under the mode of `scopes`, or pass when there is none.
    fn deny_under<'a>(
        scopes: impl Iterator<Item = &'a GateScope>,
        reason: GateReason,
    ) -> GateDecision {
        let modes: Vec<GateMode> = scopes.map(|scope| scope.mode).collect();
        if modes.is_empty() {
            GateDecision::Pass
        } else {
            decision(modes.contains(&GateMode::Enforce), false, reason, None)
        }
    }

    fn live_flow(&mut self, key: &ModelFlowKey, now: Instant) -> Option<&mut ModelFlow> {
        self.flows.get_mut(key).filter(|flow| flow.expires > now)
    }

    fn live_fragment(&self, key: &ModelFragmentKey, now: Instant) -> Option<Disposition> {
        self.fragments
            .get(key)
            .filter(|(_, expires)| *expires > now)
            .map(|(disposition, _)| *disposition)
    }

    /// Remember a fragment disposition; `false` when the table is full or
    /// the fragment has another disposition.
    fn remember(&mut self, key: ModelFragmentKey, disposition: Disposition, now: Instant) -> bool {
        match self.live_fragment(&key, now) {
            Some(existing) if existing != disposition => return false,
            None if self.live_fragments(now) >= LIMITS.fragments => return false,
            _ => {}
        }
        self.fragments
            .insert(key, (disposition, now + timeouts().fragment));
        true
    }

    fn live_fragments(&self, now: Instant) -> usize {
        self.fragments
            .values()
            .filter(|(_, expires)| *expires > now)
            .count()
    }

    fn touch(flow: &mut ModelFlow, protocol: u8, now: Instant) {
        let t = timeouts();
        let (closing, terminal) = (flow.close.closing(), flow.close.terminal());
        flow.expires = if protocol == 6 && terminal {
            flow.expires.min(now + t.tcp_closed)
        } else if protocol == 6 && closing {
            now + t.tcp_half_closed
        } else {
            now + match protocol {
                6 => t.tcp,
                17 => t.udp,
                1 | 58 => t.icmp,
                _ => t.other,
            }
        };
    }

    fn evaluate(
        &mut self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &Packet,
        now: Instant,
    ) -> GateDecision {
        let decision = self.decide(direction, peer, packet, now);
        let c = &mut self.counters;
        match &decision {
            GateDecision::Enforce { allow: true, .. } => c.enforced_allowed += 1,
            GateDecision::Enforce {
                allow: false,
                reason,
                ..
            } => {
                c.enforced_denied += 1;
                c.unbound_denied += u64::from(*reason == GateReason::Unbound);
                c.state_capacity_denied += u64::from(*reason == GateReason::StateCapacity);
            }
            GateDecision::Observe { allow: false, .. } => c.observed_denied += 1,
            _ => {}
        }
        decision
    }

    fn decide(
        &mut self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &Packet,
        now: Instant,
    ) -> GateDecision {
        // 1. Inert.
        if self.active().next().is_none()
            && self.policy.holds.inbound.is_empty()
            && self.policy.holds.outbound.is_empty()
        {
            return GateDecision::Pass;
        }
        let (remote, local) = match direction {
            PacketDirection::Inbound => (packet.src, packet.dst),
            PacketDirection::Outbound => (packet.dst, packet.src),
        };
        let binding_scopes = |model: &Self| -> Vec<GateScope> {
            model
                .active()
                .filter(|scope| {
                    scope.unbound_addresses.contains(&remote)
                        || scope.bindings.iter().any(|b| b.addresses.contains(&remote))
                        || binds_by_peer(scope, peer)
                })
                .cloned()
                .collect()
        };
        let local_scopes = |model: &Self| -> Vec<GateScope> {
            model
                .active()
                .filter(|scope| governs(scope, local))
                .cloned()
                .collect()
        };
        // 2. Malformed.
        if packet.kind == Kind::Malformed {
            if self.held(direction, peer, local, remote) {
                return decision(true, false, GateReason::Held, None);
            }
            let scopes = match direction {
                PacketDirection::Inbound => local_scopes(self),
                PacketDirection::Outbound => binding_scopes(self),
            };
            return Self::deny_under(scopes.iter(), GateReason::Malformed);
        }
        // 3. Holds.
        if self.held(direction, peer, local, remote) {
            return decision(true, false, GateReason::Held, None);
        }
        // 4. Binding.
        let bound: Vec<GateScope> = binding_level(&self.policy, peer, remote, local)
            .into_iter()
            .cloned()
            .collect();
        let transport = packet.transport();
        if bound.is_empty() {
            return match direction {
                PacketDirection::Inbound => self.unbound_inbound(peer, packet, transport, now),
                PacketDirection::Outbound => {
                    Self::deny_under(binding_scopes(self).iter(), GateReason::Unbound)
                }
            };
        }
        let [scope] = bound.as_slice() else {
            return Self::deny_under(bound.iter(), GateReason::Ambiguous);
        };
        let scope = scope.clone();
        self.bound(direction, peer, packet, &scope, now)
    }

    /// Step 4 of an inbound packet without a binding.
    fn unbound_inbound(
        &mut self,
        peer: PeerId,
        packet: &Packet,
        transport: Option<Transport>,
        now: Instant,
    ) -> GateDecision {
        let direction = PacketDirection::Inbound;
        let scopes: Vec<GateScope> = self
            .active()
            .filter(|scope| governs(scope, packet.dst))
            .cloned()
            .collect();
        if let [scope] = scopes.as_slice()
            && scope.mode == GateMode::Enforce
        {
            if let Fragment::Later(id) = packet.fragment {
                if scope.unbound.iter().any(|rule| rule.peers.contains(&peer)) {
                    return match self
                        .live_fragment(&packet.fragment_key(scope, direction, peer, id), now)
                    {
                        Some(Disposition::Pass) => GateDecision::Pass,
                        _ => decision(true, false, GateReason::OrphanFragment, None),
                    };
                }
            } else if let Some(transport) = transport
                && scope.unbound.iter().any(|rule| {
                    rule.action == UnboundAction::Pass
                        && rule.peers.contains(&peer)
                        && rule
                            .protocols
                            .iter()
                            .any(|p| protocol_matches(p, transport))
                })
            {
                if let Fragment::First(id) = packet.fragment
                    && !self.remember(
                        packet.fragment_key(scope, direction, peer, id),
                        Disposition::Pass,
                        now,
                    )
                {
                    return decision(true, false, GateReason::StateCapacity, None);
                }
                return GateDecision::Pass;
            }
        }
        Self::deny_under(scopes.iter(), GateReason::Unbound)
    }

    /// Steps 5 and 6 of a packet bound in `scope`.
    fn bound(
        &mut self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &Packet,
        scope: &GateScope,
        now: Instant,
    ) -> GateDecision {
        let (remote, local) = match direction {
            PacketDirection::Inbound => (packet.src, packet.dst),
            PacketDirection::Outbound => (packet.dst, packet.src),
        };
        let enforce = scope.mode == GateMode::Enforce;
        // 5. Bound: later fragments and ICMP errors.
        if let Fragment::Later(id) = packet.fragment {
            return match self.live_fragment(&packet.fragment_key(scope, direction, peer, id), now) {
                Some(Disposition::Allow) => decision(enforce, true, GateReason::ValidState, None),
                _ => decision(enforce, false, GateReason::OrphanFragment, None),
            };
        }
        let key = |remote_port, local_port, protocol| ModelFlowKey {
            scope: scope.id.clone(),
            peer,
            remote,
            local,
            protocol,
            remote_port,
            local_port,
        };
        if let Kind::Error(qs, qd, qsp, qdp) = packet.kind {
            // The quote, read the other way: the error's source must be the
            // quoted destination and its destination the quoted source.
            if qs != packet.dst || qd != packet.src {
                return decision(enforce, false, GateReason::Malformed, None);
            }
            let related = match direction {
                PacketDirection::Inbound => key(qdp, qsp, 17),
                PacketDirection::Outbound => key(qsp, qdp, 17),
            };
            let Some(flow) = self.live_flow(&related, now) else {
                return decision(enforce, false, GateReason::ReverseNewFlow, None);
            };
            Self::touch(flow, 17, now);
            return decision(enforce, true, GateReason::ValidState, None);
        }
        let (remote_port, local_port) = match (packet.kind, direction) {
            (Kind::Echo(_, identifier), _) => (identifier, identifier),
            (_, PacketDirection::Inbound) => (packet.src_port, packet.dst_port),
            (_, PacketDirection::Outbound) => (packet.dst_port, packet.src_port),
        };
        let protocol = packet.protocol();
        if !matches!(protocol, 1 | 58) && (remote_port == 0 || local_port == 0) {
            return decision(enforce, false, GateReason::Malformed, None);
        }
        let flow_key = key(remote_port, local_port, protocol);
        if let Some(decision) = self.established(direction, peer, packet, scope, &flow_key, now) {
            return decision;
        }
        let reverse_only = match packet.kind {
            Kind::Tcp(flags) => flags & 0x02 == 0 || flags & 0x10 != 0,
            Kind::Echo(icmp_type, _) => matches!(icmp_type, 0 | 129),
            _ => false,
        };
        if reverse_only {
            return decision(enforce, false, GateReason::ReverseNewFlow, None);
        }
        self.new_flow(direction, packet, scope, flow_key, now)
    }

    /// Step 5 for a packet of a live flow.
    fn established(
        &mut self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &Packet,
        scope: &GateScope,
        flow_key: &ModelFlowKey,
        now: Instant,
    ) -> Option<GateDecision> {
        let enforce = scope.mode == GateMode::Enforce;
        let tcp_flags = match packet.kind {
            Kind::Tcp(flags) => Some(flags),
            _ => None,
        };
        let initial_syn = tcp_flags.is_some_and(|flags| flags & 0x12 == 0x02);
        let flow = self.live_flow(flow_key, now)?;
        if initial_syn && (flow.close.closing() || direction != flow.initiator) {
            return Some(decision(enforce, false, GateReason::ReverseNewFlow, None));
        }
        Self::touch(flow, flow_key.protocol, now);
        if let Fragment::First(id) = packet.fragment
            && !self.remember(
                packet.fragment_key(scope, direction, peer, id),
                Disposition::Allow,
                now,
            )
        {
            return Some(decision(enforce, false, GateReason::StateCapacity, None));
        }
        if let Some(flags) = tcp_flags
            && flags & 0x05 != 0
            && let Some(flow) = self.flows.get_mut(flow_key)
        {
            flow.close.reset |= flags & 0x04 != 0;
            if flags & 0x01 != 0 {
                if direction == flow.initiator {
                    flow.close.fin_initiator = true;
                } else {
                    flow.close.fin_responder = true;
                }
            }
            let t = timeouts();
            let limit = if flow.close.terminal() {
                t.tcp_closed
            } else {
                t.tcp_half_closed
            };
            flow.expires = flow.expires.min(now + limit);
        }
        Some(decision(enforce, true, GateReason::ValidState, None))
    }

    /// Step 6: a new flow.
    fn new_flow(
        &mut self,
        direction: PacketDirection,
        packet: &Packet,
        scope: &GateScope,
        flow_key: ModelFlowKey,
        now: Instant,
    ) -> GateDecision {
        let (peer, transport) = (flow_key.peer, packet.transport());
        let enforce = scope.mode == GateMode::Enforce;
        let (remote, local) = (flow_key.remote, flow_key.local);
        let protocol = flow_key.protocol;
        let transport = transport.expect("a first fragment or a whole packet");
        let destination = match direction {
            PacketDirection::Inbound => local,
            PacketDirection::Outbound => remote,
        };
        let labels = binding_labels(scope, peer, remote).unwrap().clone();
        let rule = match authorize(scope, direction, &labels, destination, transport) {
            Ok(rule) => rule,
            Err(Some(suspended)) => {
                return decision(enforce, false, GateReason::Suspended, Some(suspended));
            }
            Err(None) => return decision(enforce, false, GateReason::NoGrant, None),
        };
        let live: Vec<&ModelFlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| flow.expires > now)
            .map(|(key, _)| key)
            .collect();
        let peer_flows = live.iter().filter(|key| key.peer == peer).count();
        let fragment_full = match packet.fragment {
            Fragment::First(id) => self
                .live_fragment(&packet.fragment_key(scope, direction, peer, id), now)
                .map_or_else(
                    || self.live_fragments(now) >= LIMITS.fragments,
                    |disposition| disposition != Disposition::Allow,
                ),
            _ => false,
        };
        if peer_flows >= LIMITS.flows_per_peer || live.len() >= LIMITS.flows || fragment_full {
            return decision(enforce, false, GateReason::StateCapacity, None);
        }
        let t = timeouts();
        self.flows.insert(
            flow_key,
            ModelFlow {
                initiator: direction,
                opened: transport,
                rule: rule.clone(),
                enforced: enforce,
                close: Close::default(),
                expires: now
                    + match protocol {
                        6 => t.tcp,
                        17 => t.udp,
                        _ => t.icmp,
                    },
            },
        );
        if let Fragment::First(id) = packet.fragment {
            self.fragments.insert(
                packet.fragment_key(scope, direction, peer, id),
                (Disposition::Allow, now + t.fragment),
            );
        }
        decision(enforce, true, GateReason::Granted, Some(rule))
    }

    fn replace(&mut self, policy: GatePolicy) {
        let active = |policy: &GatePolicy, id: &ScopeId| {
            policy
                .scopes
                .iter()
                .find(|scope| scope.id == *id && scope.mode != GateMode::Off)
                .cloned()
        };
        let (previous, next) = (std::mem::replace(&mut self.policy, policy), &self.policy);
        let peer_keyed =
            active_scopes(next).any(|scope| scope.bindings.iter().any(|b| b.addresses.is_empty()));
        self.flows.retain(|key, flow| {
            let Some(after) = active(next, &key.scope) else {
                return false;
            };
            // With a peer-keyed binding, a flow stays only in the scope
            // step 4 selects for it.
            if peer_keyed
                && !matches!(
                    binding_level(next, key.peer, key.remote, key.local).as_slice(),
                    [scope] if scope.id == key.scope
                )
            {
                return false;
            }
            if active(&previous, &key.scope).as_ref() == Some(&after) {
                return true;
            }
            let Some(labels) = binding_labels(&after, key.peer, key.remote) else {
                return false;
            };
            if !governs(&after, key.local) {
                return false;
            }
            let destination = match flow.initiator {
                PacketDirection::Inbound => key.local,
                PacketDirection::Outbound => key.remote,
            };
            match authorize(&after, flow.initiator, labels, destination, flow.opened) {
                Ok(rule) => {
                    flow.rule = rule;
                    flow.enforced = after.mode == GateMode::Enforce;
                    true
                }
                Err(_) => false,
            }
        });
        self.fragments.retain(|key, _| {
            active(next, &key.scope)
                .is_some_and(|after| active(&previous, &key.scope) == Some(after))
        });
    }
}

// ── The test ─────────────────────────────────────────────────────────────────

/// Run one seeded sequence; every decision seen is added to `seen`. Without
/// `unbound_addresses` every generated scope has that list emptied.
fn run(
    seed: u64,
    seen: &mut std::collections::HashSet<String>,
    unbound_addresses: bool,
    family: Family,
) {
    let mut rng = Rng(seed);
    let start = Instant::now();
    let clock = Arc::new(Mutex::new(start));
    let read = Arc::clone(&clock);
    let gate = FlowGate::with_clock(
        GateConfig {
            limits: LIMITS,
            ..GateConfig::default()
        },
        move || *read.lock().unwrap_or_else(PoisonError::into_inner),
    );
    let mut model = Model::default();
    let mut history: Vec<(PacketDirection, PeerId, Packet)> = Vec::new();
    for step in 0..STEPS {
        match rng.below(20) {
            0 => {
                let mut policy = next_policy(&mut rng, &model.policy, family);
                if !unbound_addresses {
                    for scope in &mut policy.scopes {
                        scope.unbound_addresses.clear();
                    }
                }
                gate.replace(policy.clone())
                    .expect("generated policies are valid");
                model.replace(policy);
            }
            1 => {
                let seconds = rng.pick(&[1, 10, 31, 125, 301]);
                *clock.lock().unwrap() += Duration::from_secs(seconds);
            }
            _ => {
                let (direction, peer, packet) = match history.len() {
                    0 => fresh(&mut rng, family),
                    n if rng.chance(50) => {
                        let earlier = history[rng.below(n)];
                        follow_up(&mut rng, earlier)
                    }
                    _ => fresh(&mut rng, family),
                };
                let now = *clock.lock().unwrap();
                let expected = model.evaluate(direction, peer, &packet, now);
                let bytes = packet.bytes();
                let actual = match direction {
                    PacketDirection::Inbound => gate.evaluate_inbound(peer, &bytes),
                    PacketDirection::Outbound => gate.evaluate_outbound(peer, &bytes),
                };
                if matches!(
                    actual,
                    GateDecision::Enforce { allow: true, .. }
                        | GateDecision::Observe { allow: true, .. }
                ) {
                    history.push((direction, peer, packet));
                    if history.len() > 16 {
                        history.remove(0);
                    }
                }
                seen.insert(match &actual {
                    GateDecision::Pass => "pass".to_owned(),
                    GateDecision::Observe { reason, .. } => format!("observe:{}", reason.as_str()),
                    GateDecision::Enforce { reason, .. } => reason.as_str().to_owned(),
                });
                assert_eq!(
                    actual, expected,
                    "{family:?} seed {seed} step {step}: {direction:?} {peer:?} {packet:?}\npolicy {:#?}",
                    model.policy
                );
            }
        }
        assert_eq!(
            gate.counters(),
            model.counters,
            "{family:?} seed {seed} step {step}"
        );
    }
    let _ = audit_families(&gate);
}

/// Every reason, enforced.
const REASONS: [GateReason; 11] = [
    GateReason::ValidState,
    GateReason::Granted,
    GateReason::Unbound,
    GateReason::ReverseNewFlow,
    GateReason::NoGrant,
    GateReason::Suspended,
    GateReason::Held,
    GateReason::OrphanFragment,
    GateReason::StateCapacity,
    GateReason::Ambiguous,
    GateReason::Malformed,
];

/// Every reason was enforced, packets passed and grants observed.
fn assert_coverage(seen: &std::collections::HashSet<String>) {
    for reason in REASONS {
        assert!(
            seen.contains(reason.as_str()),
            "{reason:?} never enforced: {seen:?}"
        );
    }
    assert!(
        seen.contains("pass") && seen.contains("observe:granted"),
        "{seen:?}"
    );
}

#[test]
fn the_gate_matches_the_reference_model() {
    let mut seen = std::collections::HashSet::new();
    for seed in 0..SEEDS {
        run(seed, &mut seen, true, Family::V4);
    }
    assert_coverage(&seen);
}

/// Policies that never list unbound addresses behave as before the field
/// existed.
#[test]
fn the_gate_matches_the_reference_model_without_unbound_addresses() {
    let mut seen = std::collections::HashSet::new();
    for seed in 0..SEEDS {
        run(seed, &mut seen, false, Family::V4);
    }
}

#[test]
fn the_gate_matches_the_reference_model_over_ipv6() {
    let mut seen = std::collections::HashSet::new();
    for seed in 0..SEEDS {
        run(seed, &mut seen, true, Family::V6);
    }
    assert_coverage(&seen);
}

/// Both families in every policy and in one state table: the per-peer,
/// global and fragment limits count them together.
#[test]
fn the_gate_matches_the_reference_model_over_both_families() {
    let mut seen = std::collections::HashSet::new();
    for seed in 0..SEEDS {
        run(seed, &mut seen, true, Family::Both);
    }
    assert_coverage(&seen);
}

/// Both families with peer-keyed bindings: one binding covers every address
/// of its peer in both families, the exact bindings of other scopes take
/// precedence, and migration keeps a flow only in the scope selected for it.
#[test]
fn the_gate_matches_the_reference_model_with_peer_keyed_bindings() {
    let mut seen = std::collections::HashSet::new();
    for seed in 0..SEEDS {
        run(seed, &mut seen, true, Family::PeerKeyed);
    }
    assert_coverage(&seen);
}
