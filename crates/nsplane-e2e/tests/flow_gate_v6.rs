//! The flow gate with IPv6 and peer-keyed bindings at engine level, over an in-memory
//! channel transport: two nodes `a` and `b`, where `b` runs a `GateFilter` and `a` runs no
//! filter. `b`'s gate policy is one scope governing both of `b`'s tunnel addresses that binds
//! `a`'s `PeerId` peer-keyed (no addresses: every remote address of either family) with the
//! label `source:a`. The tests check deliveries, `Event::Dropped` reasons and the gate and
//! filter counters.
//!
//! The runtime's clock is paused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::{AllowedIp, ChannelTransport, Event, PeerId, TransportId};
use nsplane_acl::gate::{
    FlowGate, GateBinding, GateConfig, GateFilter, GateGrant, GateHolds, GateMode, GatePolicy,
    GateReason, GateScope,
};
use nsplane_acl::{Direction, IpNet, Label, LabelSet, PortSet, Protocol, ProtocolMatch};
use nsplane_e2e::{Events, Node, Options, TestResult, icmp, introduce, tcp, udp};

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// A host behind `a`, which `a` forwards from; the peer-keyed binding covers it too.
const BEHIND_A: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x7f, 1);
/// An address `b` does not govern.
const FOREIGN: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99);
/// The port of the port grant on `b`.
const WEB: u16 = 443;
/// A port no port grant opens.
const SSH: u16 = 22;
/// TCP flags.
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

type GateNode = Node<ChannelTransport>;

/// The gate state of `b` the tests keep.
struct Gated {
    gate: Arc<FlowGate>,
    filter: GateFilter,
    /// `a` as `b`'s peer.
    a_peer: PeerId,
}

/// Two peers over a channel transport pair; `b` runs `GateFilter` with a fresh gate and
/// also accepts [`BEHIND_A`] from `a` as an allowed IP.
async fn gated_pair() -> TestResult<(GateNode, GateNode, Gated)> {
    let gate = FlowGate::new(GateConfig::default());
    let filter = GateFilter::new(Arc::clone(&gate));
    let a_end = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_end = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a_end, b_end);
    let a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
        builder.transport(link_a)
    })?;
    let b_filter = filter.clone();
    let b = Node::with_builder(2, b_end.0, b_end.1, Options::default(), |builder| {
        builder.transport(link_b).filter(Box::new(b_filter))
    })?;
    introduce(&a, &b, None).await?;
    let mut a_peer = a.as_peer(b.path.transport);
    a_peer.allowed_ips.push(AllowedIp {
        addr: IpAddr::V6(BEHIND_A),
        cidr: 128,
    });
    b.handle.add_or_update_peer(a_peer).await?;
    let a_peer = b.peer_of(&a).await?;
    Ok((
        a,
        b,
        Gated {
            gate,
            filter,
            a_peer,
        },
    ))
}

// ── Policies ─────────────────────────────────────────────────────────────────

fn host(ip: IpAddr) -> TestResult<IpNet> {
    let len = if ip.is_ipv4() { 32 } else { 128 };
    Ok(format!("{ip}/{len}").parse()?)
}

fn grant(
    id: &str,
    direction: Direction,
    destinations: Vec<IpNet>,
    protocols: Vec<ProtocolMatch>,
) -> GateGrant {
    GateGrant {
        id: id.into(),
        direction,
        labels: vec![Label::from("source:a")],
        destinations,
        protocols,
        suspended: false,
    }
}

/// A port grant from `a` to [`WEB`] on both of `b`'s addresses.
fn web_grant(b: &GateNode) -> TestResult<GateGrant> {
    Ok(grant(
        "web",
        Direction::Inbound,
        vec![host(IpAddr::V4(b.ip4))?, host(IpAddr::V6(b.ip6))?],
        vec![ProtocolMatch::Tcp(PortSet::single(WEB))],
    ))
}

/// A grant of every protocol from `a` to `b`'s IPv6 address.
fn a_to_b6(b: &GateNode) -> TestResult<GateGrant> {
    Ok(grant(
        "a-to-b",
        Direction::Inbound,
        vec![host(IpAddr::V6(b.ip6))?],
        vec![ProtocolMatch::Any],
    ))
}

/// Replaces `b`'s policy with one enforcing scope governing both of `b`'s addresses, with a
/// peer-keyed binding of `a` and `grants`.
fn enforce(b: &GateNode, gated: &Gated, grants: Vec<GateGrant>) -> TestResult {
    gated.gate.replace(GatePolicy {
        scopes: vec![GateScope {
            id: "scope-1".into(),
            mode: GateMode::Enforce,
            local: vec![IpAddr::V4(b.ip4), IpAddr::V6(b.ip6)],
            bindings: vec![GateBinding {
                peer: gated.a_peer,
                addresses: Vec::new(),
                labels: LabelSet::new([Label::from("source:a")]),
            }],
            unbound_addresses: Vec::new(),
            grants,
            unbound: Vec::new(),
        }],
        holds: GateHolds::default(),
    })?;
    Ok(())
}

// ── Packets and checks ───────────────────────────────────────────────────────

const fn at(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ip), port)
}

const fn at4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn tcp_flags(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
    tcp(src, dst, flags, (1, u32::from(flags & ACK != 0)), &[])
}

/// Sends `packet` from `from` and checks that `to` delivers it unchanged.
async fn delivered(from: &GateNode, to: &mut GateNode, packet: &[u8]) -> TestResult {
    from.send(packet).await?;
    let (_, got) = to.expect_delivery().await?;
    if got != packet {
        return Err("packet changed in transit".into());
    }
    Ok(())
}

/// Sends `packet` from `from`, checks that `events` (of the dropping engine) reports a drop
/// with `reason` and that `to` delivers nothing.
async fn dropped(
    from: &GateNode,
    to: &mut GateNode,
    events: &mut Events,
    packet: &[u8],
    reason: &'static str,
) -> TestResult {
    from.send(packet).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
        .await?;
    to.expect_no_delivery().await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_ipv6_flow_is_admitted_and_denied_by_a_peer_keyed_binding() -> TestResult {
    let (a, mut b, gated) = gated_pair().await?;
    let mut events = b.subscribe().await?;
    enforce(&b, &gated, vec![web_grant(&b)?])?;

    // Any remote address of `a` binds: its tunnel address and the host behind it.
    for src in [a.ip6, BEHIND_A] {
        let to_web = tcp_flags(at(src, 40000), at(b.ip6, WEB), SYN);
        delivered(&a, &mut b, &to_web).await?;
        let flow = gated
            .gate
            .find_flow(at(src, 40000), at(b.ip6, WEB), Protocol::Tcp)
            .ok_or("no flow")?;
        assert_eq!((flow.rule.as_str(), flow.enforced), ("web", true));
    }
    let to_ssh = tcp_flags(at(a.ip6, 40000), at(b.ip6, SSH), SYN);
    let no_grant = GateReason::NoGrant.drop_reason();
    dropped(&a, &mut b, &mut events, &to_ssh, no_grant).await?;
    // An unsolicited ACK is no new flow.
    let unsolicited = tcp_flags(at(a.ip6, 40001), at(b.ip6, WEB), ACK);
    let reverse = GateReason::ReverseNewFlow.drop_reason();
    dropped(&a, &mut b, &mut events, &unsolicited, reverse).await?;

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (2, 2));
    let counters = gated.gate.counters();
    assert_eq!((counters.enforced_allowed, counters.enforced_denied), (2, 2));
    assert_eq!(b.drops(no_grant).await?, 1);
    assert_eq!(b.drops(reverse).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn outbound_ipv6_to_an_enforced_peer_is_denied_while_its_inbound_flows_arrive()
-> TestResult {
    let (mut a, mut b, gated) = gated_pair().await?;
    let mut events = b.subscribe().await?;
    // Only `a` may open flows to `b`.
    enforce(&b, &gated, vec![a_to_b6(&b)?])?;
    let (a_end, b_end) = (at(a.ip6, 7000), at(b.ip6, 5000));

    // `b` opens nothing towards `a`, at any of its addresses.
    let no_grant = GateReason::NoGrant.drop_reason();
    let syn = tcp_flags(b_end, a_end, SYN);
    dropped(&b, &mut a, &mut events, &syn, no_grant).await?;
    let request = udp(b_end, at(BEHIND_A, 53), b"query");
    dropped(&b, &mut a, &mut events, &request, no_grant).await?;
    // Nor from an address the scope does not govern: unbound under the peer-keyed binding.
    let foreign = udp(at(FOREIGN, 5000), a_end, b"foreign");
    let unbound = GateReason::Unbound.drop_reason();
    dropped(&b, &mut a, &mut events, &foreign, unbound).await?;

    // `a`'s flows still arrive, and `b` answers on them.
    delivered(&a, &mut b, &tcp_flags(a_end, b_end, SYN)).await?;
    delivered(&b, &mut a, &tcp_flags(b_end, a_end, SYN_ACK)).await?;
    delivered(&a, &mut b, &tcp_flags(a_end, b_end, ACK)).await?;
    delivered(&a, &mut b, &udp(a_end, b_end, b"request")).await?;
    delivered(&b, &mut a, &udp(b_end, a_end, b"reply")).await?;
    let ping = icmp(IpAddr::V6(a.ip6), IpAddr::V6(b.ip6), (128, 0), [0, 7, 0, 1], b"ping");
    delivered(&a, &mut b, &ping).await?;
    let pong = icmp(IpAddr::V6(b.ip6), IpAddr::V6(a.ip6), (129, 0), [0, 7, 0, 1], b"ping");
    delivered(&b, &mut a, &pong).await?;

    let stats = gated.filter.stats();
    // Inbound SYN, ACK, request and ping, outbound SYN-ACK, reply and pong.
    assert_eq!((stats.gate_accepted, stats.gate_denied), (7, 3));
    let counters = gated.gate.counters();
    assert_eq!(
        (
            counters.enforced_allowed,
            counters.enforced_denied,
            counters.unbound_denied
        ),
        (7, 3, 1)
    );
    assert_eq!(b.drops(no_grant).await?, 2);
    assert_eq!(b.drops(unbound).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn one_peer_keyed_binding_governs_both_families_of_a_peer() -> TestResult {
    let (a, mut b, gated) = gated_pair().await?;
    let mut events = b.subscribe().await?;
    enforce(&b, &gated, vec![web_grant(&b)?])?;
    let no_grant = GateReason::NoGrant.drop_reason();

    let (a4, b4) = (at4(a.ip4, 40000), at4(b.ip4, WEB));
    let (a6, b6) = (at(a.ip6, 40000), at(b.ip6, WEB));
    delivered(&a, &mut b, &tcp_flags(a4, b4, SYN)).await?;
    delivered(&a, &mut b, &tcp_flags(a6, b6, SYN)).await?;
    let ssh4 = tcp_flags(a4, at4(b.ip4, SSH), SYN);
    dropped(&a, &mut b, &mut events, &ssh4, no_grant).await?;
    let ssh6 = tcp_flags(a6, at(b.ip6, SSH), SYN);
    dropped(&a, &mut b, &mut events, &ssh6, no_grant).await?;

    // One flow of each family, both in the one scope; none across families.
    for (remote, local) in [(a4, b4), (a6, b6)] {
        let flow = gated
            .gate
            .find_flow(remote, local, Protocol::Tcp)
            .ok_or("no flow")?;
        assert_eq!((flow.scope.as_str(), flow.rule.as_str()), ("scope-1", "web"));
    }
    assert!(gated.gate.find_flow(a4, b6, Protocol::Tcp).is_none());

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (2, 2));
    let counters = gated.gate.counters();
    assert_eq!((counters.enforced_allowed, counters.enforced_denied), (2, 2));
    assert_eq!(b.drops(no_grant).await?, 2);
    Ok(())
}
