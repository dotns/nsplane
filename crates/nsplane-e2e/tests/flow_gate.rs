//! The flow gate at engine level, over an in-memory channel transport: two nodes `a` and
//! `b`, where `b` runs a `GateFilter` (with an `AclFilter` behind it where a test needs one)
//! and `a` runs no filter. `b`'s gate policy is one scope governing `b`'s tunnel address that
//! binds `a`'s `PeerId` at `a`'s tunnel address with the labels `source:a` and an owner
//! label. The tests check deliveries, `Event::Dropped` reasons and the gate and filter
//! counters.
//!
//! The runtime's clock is paused. The gate's flow expiry follows an injected manual clock
//! (`FlowGate::with_clock`), so no test waits real time.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nsplane::{AllowedIp, ChannelTransport, Event, PeerId, TransportId};
use nsplane_acl::gate::{
    DivertedPacket, FlowGate, GateBinding, GateConfig, GateDecision, GateDivert, GateFilter,
    GateGrant, GateHolds, GateLimits, GateMode, GatePolicy, GateReason, GateScope, HoldRule,
    UnboundAction, UnboundRule,
};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, Direction, IpNet, Label, LabelSet, NamespaceMember,
    NamespacePolicy, OutboundRule, PeerLabelMap, PortSet, ProtocolMatch, Rule, RuleSet, reasons,
};
use nsplane_e2e::{Events, Node, Options, TestResult, icmp, introduce, tcp, udp};

/// The ACL label of `a`.
const A_LABEL: &str = "node-a";
/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// An inner source `a` carries but is not bound to.
const SPOOFED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
/// A host behind `a`, which `a` forwards from without a binding.
const BEHIND_A: Ipv4Addr = Ipv4Addr::new(100, 127, 0, 1);
/// The port of a port grant on `b`.
const WEB: u16 = 443;
/// A port no port grant opens.
const SSH: u16 = 22;
/// TCP flags.
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const RST: u8 = 0x04;

type GateNode = Node<ChannelTransport>;

/// A manual clock for the gate: a base instant plus an offset the test advances.
#[derive(Clone)]
struct Clock {
    base: Instant,
    offset_ms: Arc<AtomicU64>,
}

impl Clock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            offset_ms: Arc::default(),
        }
    }

    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
    }

    fn advance(&self, by: Duration) -> TestResult {
        self.offset_ms
            .fetch_add(u64::try_from(by.as_millis())?, Ordering::SeqCst);
        Ok(())
    }
}

/// A gate following `clock`, with the default limits.
fn clocked_gate(clock: &Clock) -> Arc<FlowGate> {
    let clock = clock.clone();
    FlowGate::with_clock(GateConfig::default(), move || clock.now())
}

fn gate() -> Arc<FlowGate> {
    FlowGate::new(GateConfig::default())
}

/// The gate state of `b` the tests keep.
struct Gated {
    gate: Arc<FlowGate>,
    filter: GateFilter,
    /// The ACL behind the gate, if any.
    acl: Option<Acl>,
    /// `a` as `b`'s peer.
    a_peer: PeerId,
}

/// An ACL engine (no policy loaded) and the filter judging with it.
struct Acl {
    engine: Arc<AclEngine>,
    filter: AclFilter,
}

/// Two peers over a channel transport pair; `b` runs `GateFilter` with `gate`, an
/// `AclFilter` behind it when `with_acl`, and `configure` applied to the filter. `b` also
/// accepts [`SPOOFED`] and [`BEHIND_A`] from `a` as allowed IPs, so those packets reach the
/// filter rather than the core's source check.
async fn gated_pair(
    gate: Arc<FlowGate>,
    with_acl: bool,
    configure: impl FnOnce(GateFilter) -> GateFilter,
) -> TestResult<(GateNode, GateNode, Gated)> {
    let identities = Arc::new(PeerLabelMap::new());
    let acl = with_acl.then(|| {
        let engine = Arc::new(AclEngine::new());
        let filter = AclFilter::with_config(
            Arc::clone(&engine),
            Arc::clone(&identities),
            AclFilterConfig::default(),
        );
        Acl { engine, filter }
    });
    let mut filter = GateFilter::new(Arc::clone(&gate));
    if let Some(acl) = &acl {
        filter = filter.with_acl(acl.filter.clone());
    }
    let filter = configure(filter);

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
    for ip in [SPOOFED, BEHIND_A] {
        a_peer.allowed_ips.push(AllowedIp {
            addr: IpAddr::V4(ip),
            cidr: 32,
        });
    }
    b.handle.add_or_update_peer(a_peer).await?;

    let a_peer = b.peer_of(&a).await?;
    identities.insert(a_peer, LabelSet::new([Label::from(A_LABEL)]));
    Ok((
        a,
        b,
        Gated {
            gate,
            filter,
            acl,
            a_peer,
        },
    ))
}

// ── Policies ─────────────────────────────────────────────────────────────────

fn host(ip: Ipv4Addr) -> TestResult<IpNet> {
    Ok(format!("{ip}/32").parse()?)
}

fn grant(
    id: &str,
    direction: Direction,
    label: &str,
    destinations: Vec<IpNet>,
    protocols: Vec<ProtocolMatch>,
) -> GateGrant {
    GateGrant {
        id: id.into(),
        direction,
        labels: vec![Label::from(label)],
        destinations,
        protocols,
        suspended: false,
    }
}

/// The owner grants (every protocol, both directions, for the owner label of `b`).
fn owner_grants(b: &GateNode) -> TestResult<Vec<GateGrant>> {
    Ok(vec![
        grant(
            "owner",
            Direction::Inbound,
            "owner:b",
            vec![host(b.ip4)?],
            vec![ProtocolMatch::Any],
        ),
        grant(
            "owner",
            Direction::Outbound,
            "owner:b",
            Vec::new(),
            vec![ProtocolMatch::Any],
        ),
    ])
}

/// A grant of every protocol from `a` to `b`.
fn a_to_b(b: &GateNode) -> TestResult<GateGrant> {
    Ok(grant(
        "a-to-b",
        Direction::Inbound,
        "source:a",
        vec![host(b.ip4)?],
        vec![ProtocolMatch::Any],
    ))
}

/// A grant of every protocol from `b` to `a`.
fn b_to_a(a: &GateNode) -> TestResult<GateGrant> {
    Ok(grant(
        "b-to-a",
        Direction::Outbound,
        "source:a",
        vec![host(a.ip4)?],
        vec![ProtocolMatch::Any],
    ))
}

/// A port grant from `a` to [`WEB`] on `b`.
fn web_grant(b: &GateNode, suspended: bool) -> TestResult<GateGrant> {
    Ok(GateGrant {
        suspended,
        ..grant(
            "web",
            Direction::Inbound,
            "source:a",
            vec![host(b.ip4)?],
            vec![ProtocolMatch::Tcp(PortSet::single(WEB))],
        )
    })
}

/// `b`'s scope in `mode`: `a` bound at its tunnel address with `source:a` and the owner
/// label of `b` (when `same_owner`) or of `a`, and `grants`.
fn scope(
    a: &GateNode,
    b: &GateNode,
    gated: &Gated,
    mode: GateMode,
    same_owner: bool,
    grants: Vec<GateGrant>,
) -> GateScope {
    let owner = if same_owner { "owner:b" } else { "owner:a" };
    GateScope {
        id: "scope-1".into(),
        mode,
        local: vec![IpAddr::V4(b.ip4)],
        bindings: vec![GateBinding {
            peer: gated.a_peer,
            addresses: vec![IpAddr::V4(a.ip4)],
            labels: LabelSet::new([Label::from("source:a"), Label::from(owner)]),
        }],
        unbound_addresses: Vec::new(),
        grants,
        unbound: Vec::new(),
    }
}

fn policy(scope: GateScope) -> GatePolicy {
    GatePolicy {
        scopes: vec![scope],
        holds: GateHolds::default(),
    }
}

/// Replaces `b`'s policy with one enforcing scope: the owner grants, then `grants`.
fn enforce(
    a: &GateNode,
    b: &GateNode,
    gated: &Gated,
    same_owner: bool,
    grants: Vec<GateGrant>,
) -> TestResult {
    let mut all = owner_grants(b)?;
    all.extend(grants);
    gated.gate.replace(policy(scope(
        a,
        b,
        gated,
        GateMode::Enforce,
        same_owner,
        all,
    )))?;
    Ok(())
}

// ── ACL rules ────────────────────────────────────────────────────────────────

/// One rule accepting every TCP and UDP flow.
fn accept_all() -> TestResult<RuleSet> {
    Ok(RuleSet::new([Rule::new(
        "all",
        vec![
            ProtocolMatch::Tcp(PortSet::Any),
            ProtocolMatch::Udp(PortSet::Any),
        ],
    )])?)
}

fn acl(gated: &Gated) -> TestResult<&Acl> {
    gated.acl.as_ref().ok_or_else(|| "no ACL".into())
}

// ── Packets and checks ───────────────────────────────────────────────────────

const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn tcp4(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
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

/// A UDP packet from `a`'s tunnel address and `port` to `b`'s.
fn udp_from_a(a: &GateNode, b: &GateNode, port: u16, dst_port: u16) -> Vec<u8> {
    udp(v4(a.ip4, port), v4(b.ip4, dst_port), b"in")
}

// ── Grants ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_owner_grant_opens_every_flow() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    enforce(&a, &b, &gated, true, Vec::new())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;
    let packet = udp_from_a(&a, &b, 40000, 7000);
    delivered(&a, &mut b, &packet).await?;

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (2, 0));
    assert_eq!(gated.gate.counters().enforced_allowed, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_source_grant_opens_every_flow() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    enforce(&a, &b, &gated, false, vec![a_to_b(&b)?])?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;
    let packet = udp_from_a(&a, &b, 40000, 7000);
    delivered(&a, &mut b, &packet).await?;
    assert_eq!(gated.filter.stats().gate_accepted, 2);
    let flow = gated
        .gate
        .find_flow(v4(a.ip4, 40000), v4(b.ip4, SSH), nsplane_acl::Protocol::Tcp)
        .ok_or("no flow")?;
    assert_eq!((flow.rule.as_str(), flow.enforced), ("a-to-b", true));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_port_grant_opens_its_port_only() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, false, vec![web_grant(&b, false)?])?;
    let to_web = tcp4(v4(a.ip4, 40000), v4(b.ip4, WEB), SYN);
    delivered(&a, &mut b, &to_web).await?;
    let to_ssh = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let no_grant = GateReason::NoGrant.drop_reason();
    dropped(&a, &mut b, &mut events, &to_ssh, no_grant).await?;

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_suspended_grant_admits_after_a_replace_lifts_it() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, false, vec![web_grant(&b, true)?])?;
    let to_web = tcp4(v4(a.ip4, 40000), v4(b.ip4, WEB), SYN);
    let suspended = GateReason::Suspended.drop_reason();
    assert_eq!(suspended, "flow gate: suspended");
    dropped(&a, &mut b, &mut events, &to_web, suspended).await?;

    enforce(&a, &b, &gated, false, vec![web_grant(&b, false)?])?;
    delivered(&a, &mut b, &to_web).await?;
    let ack = tcp4(v4(a.ip4, 40000), v4(b.ip4, WEB), ACK);
    delivered(&a, &mut b, &ack).await?;

    // Suspending again revokes the flow it admitted.
    enforce(&a, &b, &gated, false, vec![web_grant(&b, true)?])?;
    let reverse = GateReason::ReverseNewFlow.drop_reason();
    dropped(&a, &mut b, &mut events, &ack, reverse).await?;
    assert_eq!(b.drops(suspended).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cross_owner_without_a_grant_is_dropped() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, false, Vec::new())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let no_grant = GateReason::NoGrant.drop_reason();
    assert_eq!(no_grant, "flow gate: no grant");
    dropped(&a, &mut b, &mut events, &packet, no_grant).await?;

    assert_eq!(b.drops(no_grant).await?, 1);
    assert_eq!(gated.filter.stats().gate_denied, 1);
    assert_eq!(gated.gate.counters().enforced_denied, 1);
    Ok(())
}

// ── Bindings ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_spoofed_inner_source_is_unbound() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, true, Vec::new())?;
    // `a` may carry `SPOOFED` (an allowed IP), but no binding pairs it with `a`.
    let spoofed = tcp4(v4(SPOOFED, 40000), v4(b.ip4, SSH), SYN);
    let reason = GateReason::Unbound.drop_reason();
    dropped(&a, &mut b, &mut events, &spoofed, reason).await?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;

    assert_eq!(gated.gate.counters().unbound_denied, 1);
    assert_eq!(b.drops(reason).await?, 1);
    Ok(())
}

// ── State ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn replies_to_b_s_flows_pass_and_unsolicited_acks_are_reverse_new_flows() -> TestResult {
    let (mut a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    // Only `b` may open flows to `a`.
    enforce(&a, &b, &gated, false, vec![b_to_a(&a)?])?;
    let (b_end, a_end) = (v4(b.ip4, 5000), v4(a.ip4, SSH));

    delivered(&b, &mut a, &tcp4(b_end, a_end, SYN)).await?;
    delivered(&a, &mut b, &tcp4(a_end, b_end, SYN_ACK)).await?;
    delivered(&a, &mut b, &tcp4(a_end, b_end, ACK)).await?;
    delivered(&b, &mut a, &udp(b_end, a_end, b"request")).await?;
    delivered(&a, &mut b, &udp(a_end, b_end, b"reply")).await?;

    let reverse = GateReason::ReverseNewFlow.drop_reason();
    let unsolicited = tcp4(v4(a.ip4, SSH + 1), b_end, ACK);
    dropped(&a, &mut b, &mut events, &unsolicited, reverse).await?;
    // A new flow from `a` is not covered by `b`'s grant.
    let new_flow = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let no_grant = GateReason::NoGrant.drop_reason();
    dropped(&a, &mut b, &mut events, &new_flow, no_grant).await?;

    let stats = gated.filter.stats();
    // Outbound SYN and request, inbound SYN-ACK, ACK and reply.
    assert_eq!((stats.gate_accepted, stats.gate_denied), (5, 2));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_terminated_tcp_flow_refuses_a_new_syn_until_its_tail_expires() -> TestResult {
    let clock = Clock::new();
    let (a, mut b, gated) = gated_pair(clocked_gate(&clock), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, false, vec![a_to_b(&b)?])?;
    let (a_end, b_end) = (v4(a.ip4, 40000), v4(b.ip4, SSH));
    let syn = tcp4(a_end, b_end, SYN);

    delivered(&a, &mut b, &syn).await?;
    delivered(&a, &mut b, &tcp4(a_end, b_end, RST)).await?;
    let reverse = GateReason::ReverseNewFlow.drop_reason();
    dropped(&a, &mut b, &mut events, &syn, reverse).await?;

    // The closed tail lasts 30 s; then the five-tuple opens a new flow.
    clock.advance(Duration::from_secs(31))?;
    delivered(&a, &mut b, &syn).await?;
    assert_eq!(b.drops(reverse).await?, 1);
    Ok(())
}

// ── Limits ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_full_per_peer_table_drops_new_flows() -> TestResult {
    let gate = FlowGate::new(GateConfig {
        limits: GateLimits {
            flows_per_peer: 2,
            ..GateLimits::default()
        },
        ..GateConfig::default()
    });
    let (a, mut b, gated) = gated_pair(gate, false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, true, Vec::new())?;
    for port in [40000, 40001] {
        let packet = udp_from_a(&a, &b, port, 7000);
        delivered(&a, &mut b, &packet).await?;
    }
    let reason = GateReason::StateCapacity.drop_reason();
    let third = udp_from_a(&a, &b, 40002, 7000);
    dropped(&a, &mut b, &mut events, &third, reason).await?;
    // Established flows still pass; the table never evicts them.
    let packet = udp_from_a(&a, &b, 40000, 7000);
    delivered(&a, &mut b, &packet).await?;

    assert_eq!(gated.gate.counters().state_capacity_denied, 1);
    assert_eq!(b.drops(reason).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn expired_flows_make_room_for_new_ones() -> TestResult {
    let clock = Clock::new();
    let (a, mut b, gated) = gated_pair(clocked_gate(&clock), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, true, Vec::new())?;
    // Fill `a`'s 2,048 flows straight through the shared gate, then send through the
    // engines.
    for port in 0..2048_u16 {
        let packet = udp_from_a(&a, &b, 10000 + port, 7000);
        assert!(matches!(
            gated.gate.evaluate_inbound(gated.a_peer, &packet),
            GateDecision::Enforce { allow: true, .. }
        ));
    }
    let next = udp_from_a(&a, &b, 40000, 7000);
    let reason = GateReason::StateCapacity.drop_reason();
    dropped(&a, &mut b, &mut events, &next, reason).await?;

    // UDP flows idle out after 2 min; the full table sweeps them for the new flow.
    clock.advance(Duration::from_secs(121))?;
    delivered(&a, &mut b, &next).await?;
    assert_eq!(gated.gate.counters().state_capacity_denied, 1);
    Ok(())
}

// ── Modes ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn observe_leaves_the_verdict_to_the_acl_and_counts() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    let acl = acl(&gated)?;
    // Cross owner without a grant: enforcement would deny.
    gated.gate.replace(policy(scope(
        &a,
        &b,
        &gated,
        GateMode::Observe,
        false,
        Vec::new(),
    )))?;

    acl.engine.install(RuleSet::empty());
    let first = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    dropped(&a, &mut b, &mut events, &first, reasons::DENIED).await?;
    acl.engine.install(accept_all()?);
    let packet = tcp4(v4(a.ip4, 40001), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;

    assert_eq!(gated.gate.counters().observed_denied, 2);
    let stats = gated.filter.stats();
    assert_eq!(
        (stats.passed_to_acl, stats.gate_accepted, stats.gate_denied),
        (2, 0, 0)
    );
    let acl_stats = acl.filter.stats();
    assert_eq!((acl_stats.accepted, acl_stats.denied), (1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_enforced_allow_skips_an_acl_that_would_deny() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), true, |f| f).await?;
    let acl = acl(&gated)?;
    acl.engine.install(RuleSet::empty());
    enforce(&a, &b, &gated, true, Vec::new())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_accepted, stats.passed_to_acl), (1, 0));
    assert_eq!(acl.filter.stats().denied, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn off_and_removed_scopes_leave_the_verdict_to_the_acl() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    let acl = acl(&gated)?;
    acl.engine.install(accept_all()?);
    let (a_ip, b_ip) = (a.ip4, b.ip4);
    let packet = |port| tcp4(v4(a_ip, port), v4(b_ip, SSH), SYN);
    let no_grant = GateReason::NoGrant.drop_reason();

    // Without a policy the gate passes everything.
    delivered(&a, &mut b, &packet(40000)).await?;
    let enforced = scope(&a, &b, &gated, GateMode::Enforce, false, Vec::new());
    gated.gate.replace(policy(enforced.clone()))?;
    dropped(&a, &mut b, &mut events, &packet(40001), no_grant).await?;

    // An Off scope is the same as none.
    gated.gate.replace(policy(GateScope {
        mode: GateMode::Off,
        ..enforced.clone()
    }))?;
    delivered(&a, &mut b, &packet(40002)).await?;
    acl.engine.install(RuleSet::empty());
    dropped(&a, &mut b, &mut events, &packet(40003), reasons::DENIED).await?;

    // Enforce again, then the scope is removed.
    gated.gate.replace(policy(enforced))?;
    dropped(&a, &mut b, &mut events, &packet(40004), no_grant).await?;
    gated.gate.replace(GatePolicy::default())?;
    dropped(&a, &mut b, &mut events, &packet(40005), reasons::DENIED).await?;

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_denied, stats.passed_to_acl), (2, 4));
    Ok(())
}

// ── Holds ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_held_peer_is_held_until_the_hold_is_released() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    let mut held = policy(scope(
        &a,
        &b,
        &gated,
        GateMode::Enforce,
        true,
        owner_grants(&b)?,
    ));
    held.holds.inbound.push(HoldRule {
        peers: Some(vec![gated.a_peer]),
        local: vec![host(b.ip4)?],
        remote: Vec::new(),
    });
    gated.gate.replace(held.clone())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let reason = GateReason::Held.drop_reason();
    dropped(&a, &mut b, &mut events, &packet, reason).await?;
    // Holds apply in every mode.
    held.scopes[0].mode = GateMode::Observe;
    gated.gate.replace(held.clone())?;
    dropped(&a, &mut b, &mut events, &packet, reason).await?;

    held.scopes[0].mode = GateMode::Enforce;
    held.holds.release.push((gated.a_peer, IpAddr::V4(a.ip4)));
    gated.gate.replace(held)?;
    delivered(&a, &mut b, &packet).await?;
    assert_eq!(b.drops(reason).await?, 2);
    Ok(())
}

// ── Unbound rules ────────────────────────────────────────────────────────────

/// An enforcing scope binding nothing at `b`, with `unbound` rules for `a`.
fn unbound_policy(b: &GateNode, unbound: Vec<UnboundRule>) -> GatePolicy {
    policy(GateScope {
        id: "scope-1".into(),
        mode: GateMode::Enforce,
        local: vec![IpAddr::V4(b.ip4)],
        bindings: Vec::new(),
        unbound_addresses: Vec::new(),
        grants: Vec::new(),
        unbound,
    })
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_unbound_pass_rule_hands_its_packets_to_the_acl() -> TestResult {
    let (a, mut b, gated) = gated_pair(gate(), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    let acl = acl(&gated)?;
    acl.engine.install(accept_all()?);
    gated.gate.replace(unbound_policy(
        &b,
        vec![UnboundRule {
            id: "pass".into(),
            peers: vec![gated.a_peer],
            action: UnboundAction::Pass,
            protocols: vec![ProtocolMatch::Tcp(PortSet::single(WEB))],
        }],
    ))?;
    let to_web = tcp4(v4(BEHIND_A, 40000), v4(b.ip4, WEB), SYN);
    delivered(&a, &mut b, &to_web).await?;
    let to_ssh = tcp4(v4(BEHIND_A, 40000), v4(b.ip4, SSH), SYN);
    let unbound = GateReason::Unbound.drop_reason();
    dropped(&a, &mut b, &mut events, &to_ssh, unbound).await?;

    // The ACL still decides the passed packet.
    acl.engine.install(RuleSet::empty());
    dropped(&a, &mut b, &mut events, &to_web, reasons::DENIED).await?;
    let stats = gated.filter.stats();
    assert_eq!((stats.passed_to_acl, stats.gate_denied), (2, 1));
    Ok(())
}

// ── ICMP errors ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn icmp_errors_pass_only_for_their_flow() -> TestResult {
    let (mut a, mut b, gated) = gated_pair(gate(), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &gated, false, vec![b_to_a(&a)?])?;
    let request = udp(v4(b.ip4, 5000), v4(a.ip4, 53), b"request");
    delivered(&b, &mut a, &request).await?;

    // Destination unreachable, port unreachable, quoting `b`'s request.
    let unreachable = (3, 3);
    let related = icmp(
        IpAddr::V4(a.ip4),
        IpAddr::V4(b.ip4),
        unreachable,
        [0; 4],
        &request,
    );
    delivered(&a, &mut b, &related).await?;
    let other = udp(v4(b.ip4, 5001), v4(a.ip4, 53), b"request");
    let unrelated = icmp(
        IpAddr::V4(a.ip4),
        IpAddr::V4(b.ip4),
        unreachable,
        [0; 4],
        &other,
    );
    let reason = GateReason::ReverseNewFlow.drop_reason();
    dropped(&a, &mut b, &mut events, &unrelated, reason).await?;
    assert_eq!(gated.filter.stats().gate_denied, 1);
    Ok(())
}

// ── Divert ───────────────────────────────────────────────────────────────────

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

/// A divert rule for every TCP and UDP packet of `peer`.
fn divert_rule(peer: PeerId) -> UnboundRule {
    UnboundRule {
        id: "divert:gw-1".into(),
        peers: vec![peer],
        action: UnboundAction::Divert,
        protocols: vec![
            ProtocolMatch::Tcp(PortSet::Any),
            ProtocolMatch::Udp(PortSet::Any),
        ],
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_unbound_packet_is_diverted() -> TestResult {
    let queue = Queue::new(1);
    let divert = queue.clone();
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f.with_divert(divert)).await?;
    let mut events = b.subscribe().await?;
    gated
        .gate
        .replace(unbound_policy(&b, vec![divert_rule(gated.a_peer)]))?;
    let reply = udp(v4(BEHIND_A, 19999), v4(b.ip4, 49152), b"reply");

    a.send(&reply).await?;
    b.expect_no_delivery().await?;
    events
        .expect_none(|e| matches!(e, Event::Dropped { .. }))
        .await?;
    {
        let taken = queue.taken();
        let [(peer, packet)] = taken.as_slice() else {
            return Err(format!("{} diverted", taken.len()).into());
        };
        assert_eq!(*peer, gated.a_peer);
        assert_eq!(packet.packet(), reply.as_slice());
        assert_eq!(packet.rule().as_str(), "divert:gw-1");
        assert_eq!(packet.generation(), gated.gate.generation());
    }

    // The divert is full: the next packet is dropped.
    let reason = GateReason::Unbound.drop_reason();
    dropped(&a, &mut b, &mut events, &reply, reason).await?;
    let stats = gated.filter.stats();
    assert_eq!(
        (stats.diverted, stats.divert_rejected, stats.gate_denied),
        (1, 1, 1)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_diverted_packet_is_stale_after_a_replace() -> TestResult {
    let queue = Queue::new(8);
    let divert = queue.clone();
    let (a, mut b, gated) = gated_pair(gate(), false, |f| f.with_divert(divert)).await?;
    let policy = unbound_policy(&b, vec![divert_rule(gated.a_peer)]);
    gated.gate.replace(policy.clone())?;
    let reply = udp(v4(BEHIND_A, 19999), v4(b.ip4, 49152), b"reply");
    a.send(&reply).await?;
    b.expect_no_delivery().await?;
    let first = queue.taken().first().map(|(_, packet)| packet.generation());
    assert_eq!(first, Some(gated.gate.generation()), "current when taken");

    // Any replace, even of the same policy, makes queued packets stale.
    gated.gate.replace(policy)?;
    assert_ne!(first, Some(gated.gate.generation()));
    a.send(&reply).await?;
    b.expect_no_delivery().await?;
    let taken = queue.taken();
    let generations: Vec<u64> = taken
        .iter()
        .map(|(_, packet)| packet.generation())
        .collect();
    assert_eq!(generations.len(), 2);
    assert_eq!(generations.last(), Some(&gated.gate.generation()));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_unbound_address_is_governed_and_never_diverted() -> TestResult {
    let queue = Queue::new(8);
    let divert = queue.clone();
    let (mut a, mut b, gated) = gated_pair(gate(), false, |f| f.with_divert(divert)).await?;
    let mut events = b.subscribe().await?;
    // `BEHIND_A` belongs to the scope without a binding; `a` also has a divert rule.
    let mut scope = scope(&a, &b, &gated, GateMode::Enforce, false, vec![b_to_a(&a)?]);
    scope.unbound_addresses = vec![IpAddr::V4(BEHIND_A)];
    scope.unbound = vec![divert_rule(gated.a_peer)];
    gated.gate.replace(policy(scope.clone()))?;

    // Enforce: outbound to it is denied as unbound.
    let to_it = udp(v4(b.ip4, 5000), v4(BEHIND_A, 53), b"out");
    let unbound = GateReason::Unbound.drop_reason();
    dropped(&b, &mut a, &mut events, &to_it, unbound).await?;
    // No divert: a packet from it is dropped, not handed to the divert.
    let from_it = udp(v4(BEHIND_A, 19999), v4(b.ip4, 49152), b"reply");
    dropped(&a, &mut b, &mut events, &from_it, unbound).await?;
    assert!(queue.taken().is_empty());
    assert_eq!(gated.gate.counters().unbound_denied, 2);

    // Observe: reported, delivered.
    scope.mode = GateMode::Observe;
    gated.gate.replace(policy(scope))?;
    delivered(&b, &mut a, &to_it).await?;
    assert_eq!(gated.gate.counters().observed_denied, 1);
    let stats = gated.filter.stats();
    assert_eq!((stats.diverted, stats.gate_denied), (0, 2));
    Ok(())
}

// ── Outbound ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn outbound_without_a_grant_is_dropped_by_the_gate() -> TestResult {
    let (mut a, b, gated) = gated_pair(gate(), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    acl(&gated)?.engine.install(accept_all()?);
    // Only `a` may open flows to `b`.
    enforce(&a, &b, &gated, false, vec![a_to_b(&b)?])?;
    let packet = tcp4(v4(b.ip4, 5000), v4(a.ip4, SSH), SYN);
    let reason = GateReason::NoGrant.drop_reason();
    dropped(&b, &mut a, &mut events, &packet, reason).await?;

    let stats = gated.filter.stats();
    assert_eq!((stats.gate_denied, stats.passed_to_acl), (1, 0));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_acl_outbound_runs_only_when_opted_in() -> TestResult {
    for opt_in in [false, true] {
        let (mut a, b, gated) = gated_pair(gate(), true, |f| f.with_acl_outbound(opt_in)).await?;
        let mut events = b.subscribe().await?;
        // `a`'s namespace restricts outbound traffic to it to TCP 443.
        acl(&gated)?.engine.store_namespace(
            "team-a",
            NamespacePolicy {
                members: vec![NamespaceMember {
                    label: Label::from(A_LABEL),
                    addresses: vec![host(a.ip4)?],
                }],
                outbound: Some(vec![OutboundRule::new(
                    "https",
                    vec![ProtocolMatch::Tcp(PortSet::single(443))],
                )]),
                ..NamespacePolicy::default()
            },
        )?;
        let ssh = tcp4(v4(b.ip4, 5000), v4(a.ip4, SSH), SYN);
        if opt_in {
            dropped(&b, &mut a, &mut events, &ssh, reasons::OUTBOUND).await?;
            let https = tcp4(v4(b.ip4, 5000), v4(a.ip4, 443), SYN);
            delivered(&b, &mut a, &https).await?;
            assert_eq!(gated.filter.stats().passed_to_acl, 2);
        } else {
            delivered(&b, &mut a, &ssh).await?;
            assert_eq!(gated.filter.stats().passed_to_acl, 0);
        }
    }
    Ok(())
}
