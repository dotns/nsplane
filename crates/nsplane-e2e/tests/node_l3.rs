//! The node L3 gate at engine level, over an in-memory channel transport: two nodes `a` and
//! `b`, where `b` runs a `NodeL3Filter` (with an `AclFilter` behind it where a test needs
//! one) and `a` runs no filter. `a`'s WireGuard public key is mapped in a `PeerKeyMap`, and
//! the gate's snapshots use `a`'s real key and both nodes' tunnel addresses: `b` is the
//! local Node (machine `machine-b`), `a` the remote one. The tests check deliveries,
//! `Event::Dropped` reasons and the gate and filter counters.
//!
//! The runtime's clock is paused. The gate's flow expiry follows an injected manual clock
//! (`NodeL3Gate::with_clock`), so no test waits real time.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nsplane::{AllowedIp, ChannelTransport, Event, PeerId, TransportId};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclFilterConfig, AclPolicy, AclRule, GatewayConsumerPacket,
    GatewayConsumerSink, Label, LabelSet, NODE_L3_SCHEMA_VERSION, NamespaceMember, NamespacePolicy,
    NodeL3Config, NodeL3Decision, NodeL3Filter, NodeL3Gate, NodeL3Grant, NodeL3Mode, NodeL3Node,
    NodeL3PeerBinding, NodeL3PeerPolicyRequirement, NodeL3Reason, NodeL3Resource,
    NodeL3ServiceEndpoint, NodeL3ServiceProtocol, NodeL3Transport, NodeL3TransportPeer,
    OutboundRule, PeerKeyMap, PeerLabelMap, reasons,
};
use nsplane_e2e::{Events, Node, Options, TestResult, icmp, introduce, tcp, udp};

/// Capacity of the channel transport pair.
/// The ACL label of `a`.
const A_LABEL: &str = "node-a";
const CAPACITY: usize = 1024;
/// The machine `b`'s gate is bound to.
const MACHINE: &str = "machine-b";
/// The control source of [`NodeL3Gate::apply`] for [`MACHINE`].
const SOURCE: &str = "target:machine-b";
const NETWORK: &str = "network-1";
/// An inner source `a` carries but is not bound to.
const SPOOFED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
/// A host behind `a` when `a` is a gateway carrier.
const GATEWAY_TARGET: Ipv4Addr = Ipv4Addr::new(100, 127, 0, 1);
/// The Service listener on `b`.
const SERVICE_PORT: u16 = 443;
/// A raw Node port no Grant opens on its own.
const SSH: u16 = 22;
/// TCP flags.
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const RST: u8 = 0x04;

type L3Node = Node<ChannelTransport>;

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

/// A gate for [`MACHINE`] following `clock`, with the default limits.
fn clocked_gate(clock: &Clock) -> Arc<NodeL3Gate> {
    let clock = clock.clone();
    NodeL3Gate::with_clock([MACHINE.to_owned()], move || clock.now())
}

/// The node L3 state of `b` the tests keep.
struct L3 {
    gate: Arc<NodeL3Gate>,
    filter: NodeL3Filter,
    /// The ACL behind the gate, if any.
    acl: Option<Acl>,
    /// `a`'s WireGuard public key.
    a_key: [u8; 32],
}

/// An ACL engine (no policy loaded) and the filter judging with it.
struct Acl {
    engine: Arc<AclEngine>,
    filter: AclFilter,
}

/// Two peers over a channel transport pair; `b` runs `NodeL3Filter` with `gate`, an
/// `AclFilter` behind it when `with_acl`, and `configure` applied to the filter. `b` also
/// accepts [`SPOOFED`] and [`GATEWAY_TARGET`] from `a` as allowed IPs, so those packets
/// reach the filter rather than the core's source check.
async fn l3_pair(
    gate: Arc<NodeL3Gate>,
    with_acl: bool,
    configure: impl FnOnce(NodeL3Filter) -> NodeL3Filter,
) -> TestResult<(L3Node, L3Node, L3)> {
    let keys = Arc::new(PeerKeyMap::new());
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
    let mut filter = NodeL3Filter::new(Arc::clone(&gate), Arc::clone(&keys));
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
    for ip in [SPOOFED, GATEWAY_TARGET] {
        a_peer.allowed_ips.push(AllowedIp {
            addr: IpAddr::V4(ip),
            cidr: 32,
        });
    }
    b.handle.add_or_update_peer(a_peer).await?;

    let a_key = a.public().to_bytes();
    let peer_a = b.peer_of(&a).await?;
    keys.insert(peer_a, a_key);
    identities.insert(peer_a, LabelSet::new([Label::from(A_LABEL)]));
    Ok((
        a,
        b,
        L3 {
            gate,
            filter,
            acl,
            a_key,
        },
    ))
}

// ── Snapshots ────────────────────────────────────────────────────────────────

fn node(id: &str, owner: &str, ip: Ipv4Addr) -> NodeL3Node {
    NodeL3Node {
        node_id: id.to_owned(),
        owner_id: owner.to_owned(),
        ip,
    }
}

/// `b`'s snapshot: local Node `node-b` of `owner-b`, `a` bound as `node-a` (of `owner-b`
/// when `same_owner`, else `owner-a`), a Service `web` on `node-b` TCP [`SERVICE_PORT`], and
/// `grants`.
fn config(
    a: &L3Node,
    b: &L3Node,
    l3: &L3,
    mode: NodeL3Mode,
    same_owner: bool,
    grants: Vec<NodeL3Grant>,
) -> NodeL3Config {
    let a_owner = if same_owner { "owner-b" } else { "owner-a" };
    NodeL3Config {
        schema_version: NODE_L3_SCHEMA_VERSION,
        network_id: NETWORK.to_owned(),
        target_machine_id: MACHINE.to_owned(),
        generation: 1,
        mode,
        local_node: node("node-b", "owner-b", b.ip4),
        bindings: vec![NodeL3PeerBinding {
            peer_public_key: l3.a_key,
            node_id: "node-a".to_owned(),
            owner_id: a_owner.to_owned(),
            ip: a.ip4,
        }],
        services: vec![NodeL3ServiceEndpoint {
            service_id: "web".to_owned(),
            node_id: "node-b".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: SERVICE_PORT,
        }],
        grants,
    }
}

/// A Node Grant from `source` to `target`.
fn node_grant(source: &str, target: &str) -> NodeL3Grant {
    NodeL3Grant {
        grant_id: format!("node-{source}-{target}"),
        source_node_id: source.to_owned(),
        resource: NodeL3Resource::Node {
            node_id: target.to_owned(),
        },
    }
}

/// A Service Grant from `node-a` to `web` on `node-b`.
fn service_grant() -> NodeL3Grant {
    NodeL3Grant {
        grant_id: "service-web".to_owned(),
        source_node_id: "node-a".to_owned(),
        resource: NodeL3Resource::Service {
            service_id: "web".to_owned(),
            node_id: "node-b".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: SERVICE_PORT,
        },
    }
}

/// `b`'s WireGuard projection: `a` carries its Node address with the Enforce marker of
/// generation `generation`.
fn marked_projection(
    a: &L3Node,
    b: &L3Node,
    l3: &L3,
    generation: u64,
) -> TestResult<NodeL3Transport> {
    Ok(NodeL3Transport {
        local_ip: b.ip4,
        peers: vec![NodeL3TransportPeer {
            public_key: l3.a_key,
            allowed_ips: vec![format!("{}/32", a.ip4).parse()?],
            gateway_id: None,
            relayed: false,
            node_l3_policy: Some(NodeL3PeerPolicyRequirement {
                network_id: NETWORK.to_owned(),
                generation,
                mode: NodeL3Mode::Enforce,
                node_ips: vec![a.ip4],
            }),
        }],
    })
}

/// Applies an Enforce snapshot (generation 1) and the matching marked projection.
fn enforce(
    a: &L3Node,
    b: &L3Node,
    l3: &L3,
    same_owner: bool,
    grants: Vec<NodeL3Grant>,
) -> TestResult {
    l3.gate
        .apply(config(a, b, l3, NodeL3Mode::Enforce, same_owner, grants))?;
    l3.gate
        .replace_transport_projection(&marked_projection(a, b, l3, 1)?)?;
    Ok(())
}

// ── ACL policies ─────────────────────────────────────────────────────────────

fn accept_all() -> AclPolicy {
    AclPolicy {
        acls: vec![AclRule {
            action: AclAction::Accept,
            src: vec!["*".to_owned()],
            dst: vec!["*:*".to_owned()],
            proto: None,
        }],
        ..AclPolicy::default()
    }
}

fn acl(l3: &L3) -> TestResult<&Acl> {
    l3.acl.as_ref().ok_or_else(|| "no ACL".into())
}

// ── Packets and checks ───────────────────────────────────────────────────────

const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn tcp4(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
    tcp(src, dst, flags, (1, u32::from(flags & ACK != 0)), &[])
}

/// Sends `packet` from `from` and checks that `to` delivers it unchanged.
async fn delivered(from: &L3Node, to: &mut L3Node, packet: &[u8]) -> TestResult {
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
    from: &L3Node,
    to: &mut L3Node,
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
fn udp_from_a(a: &L3Node, b: &L3Node, port: u16, dst_port: u16) -> Vec<u8> {
    udp(v4(a.ip4, port), v4(b.ip4, dst_port), b"in")
}

// ── Grants ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn same_owner_opens_the_node() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    enforce(&a, &b, &l3, true, Vec::new())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;
    let packet = udp_from_a(&a, &b, 40000, 7000);
    delivered(&a, &mut b, &packet).await?;

    let stats = l3.filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (2, 0));
    assert_eq!(l3.gate.counters().enforced_allowed, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_node_grant_opens_the_node() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    enforce(&a, &b, &l3, false, vec![node_grant("node-a", "node-b")])?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;
    let packet = udp_from_a(&a, &b, 40000, 7000);
    delivered(&a, &mut b, &packet).await?;
    assert_eq!(l3.filter.stats().gate_accepted, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_service_grant_needs_the_provider_listener() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, false, vec![service_grant()])?;
    let to_web = tcp4(v4(a.ip4, 40000), v4(b.ip4, SERVICE_PORT), SYN);
    let service_projection = NodeL3Reason::ServiceProjection.drop_reason();
    dropped(&a, &mut b, &mut events, &to_web, service_projection).await?;

    l3.gate.replace_provider_listeners(
        MACHINE,
        [("web".to_owned(), NodeL3ServiceProtocol::Tcp, SERVICE_PORT)],
    );
    delivered(&a, &mut b, &to_web).await?;
    // The Service Grant opens the listener only, not the Node.
    let to_ssh = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let no_grant = NodeL3Reason::NoGrant.drop_reason();
    dropped(&a, &mut b, &mut events, &to_ssh, no_grant).await?;

    let stats = l3.filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (1, 2));
    assert_eq!(b.drops(service_projection).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cross_owner_without_a_grant_is_dropped() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, false, Vec::new())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let no_grant = NodeL3Reason::NoGrant.drop_reason();
    assert_eq!(no_grant, "node l3: no grant");
    dropped(&a, &mut b, &mut events, &packet, no_grant).await?;

    assert_eq!(b.drops(no_grant).await?, 1);
    assert_eq!(l3.filter.stats().gate_denied, 1);
    assert_eq!(l3.gate.counters().enforced_denied, 1);
    Ok(())
}

// ── Source binding ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_spoofed_inner_source_is_dropped() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, true, Vec::new())?;
    // `a` may carry `SPOOFED` (an allowed IP), but no binding pairs it with `a`'s key.
    let spoofed = tcp4(v4(SPOOFED, 40000), v4(b.ip4, SSH), SYN);
    let reason = NodeL3Reason::SourceBinding.drop_reason();
    dropped(&a, &mut b, &mut events, &spoofed, reason).await?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;

    assert_eq!(l3.gate.counters().source_binding_denied, 1);
    assert_eq!(b.drops(reason).await?, 1);
    Ok(())
}

// ── State ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn replies_to_b_s_flows_pass_and_unsolicited_acks_are_reverse_new_flows() -> TestResult {
    let (mut a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    // Only `b` may open flows to `a`.
    enforce(&a, &b, &l3, false, vec![node_grant("node-b", "node-a")])?;
    let (b_end, a_end) = (v4(b.ip4, 5000), v4(a.ip4, SSH));

    delivered(&b, &mut a, &tcp4(b_end, a_end, SYN)).await?;
    delivered(&a, &mut b, &tcp4(a_end, b_end, SYN_ACK)).await?;
    delivered(&a, &mut b, &tcp4(a_end, b_end, ACK)).await?;
    delivered(&b, &mut a, &udp(b_end, a_end, b"request")).await?;
    delivered(&a, &mut b, &udp(a_end, b_end, b"reply")).await?;

    let reverse = NodeL3Reason::ReverseNewFlow.drop_reason();
    let unsolicited = tcp4(v4(a.ip4, SSH + 1), b_end, ACK);
    dropped(&a, &mut b, &mut events, &unsolicited, reverse).await?;
    // A new flow from `a` is not covered by `b`'s Grant.
    let new_flow = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    let no_grant = NodeL3Reason::NoGrant.drop_reason();
    dropped(&a, &mut b, &mut events, &new_flow, no_grant).await?;

    let stats = l3.filter.stats();
    // Outbound SYN and request, inbound SYN-ACK, ACK and reply.
    assert_eq!((stats.gate_accepted, stats.gate_denied), (5, 2));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_terminated_tcp_flow_refuses_a_new_syn_until_its_tail_expires() -> TestResult {
    let clock = Clock::new();
    let (a, mut b, l3) = l3_pair(clocked_gate(&clock), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, false, vec![node_grant("node-a", "node-b")])?;
    let (a_end, b_end) = (v4(a.ip4, 40000), v4(b.ip4, SSH));
    let syn = tcp4(a_end, b_end, SYN);

    delivered(&a, &mut b, &syn).await?;
    delivered(&a, &mut b, &tcp4(a_end, b_end, RST)).await?;
    let reverse = NodeL3Reason::ReverseNewFlow.drop_reason();
    dropped(&a, &mut b, &mut events, &syn, reverse).await?;

    // The terminal tail lasts 30 s; then the five-tuple opens a new flow.
    clock.advance(Duration::from_secs(31))?;
    delivered(&a, &mut b, &syn).await?;
    assert_eq!(b.drops(reverse).await?, 1);
    Ok(())
}

// ── Limits ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_full_per_peer_table_drops_new_flows() -> TestResult {
    let gate = NodeL3Gate::with_limits(MACHINE, 16_384, 2, 64);
    let (a, mut b, l3) = l3_pair(gate, false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, true, Vec::new())?;
    for port in [40000, 40001] {
        let packet = udp_from_a(&a, &b, port, 7000);
        delivered(&a, &mut b, &packet).await?;
    }
    let reason = NodeL3Reason::StateCapacity.drop_reason();
    let third = udp_from_a(&a, &b, 40002, 7000);
    dropped(&a, &mut b, &mut events, &third, reason).await?;
    // Established flows still pass; the table never evicts them.
    let packet = udp_from_a(&a, &b, 40000, 7000);
    delivered(&a, &mut b, &packet).await?;

    assert_eq!(l3.gate.counters().state_capacity_denied, 1);
    assert_eq!(b.drops(reason).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn expired_flows_make_room_for_new_ones() -> TestResult {
    let clock = Clock::new();
    let (a, mut b, l3) = l3_pair(clocked_gate(&clock), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, true, Vec::new())?;
    // Fill `a`'s 2,048 flows straight through the shared gate, then send through the
    // engines.
    for port in 0..2048_u16 {
        let packet = udp_from_a(&a, &b, 10000 + port, 7000);
        assert!(matches!(
            l3.gate.evaluate_inbound(l3.a_key, &packet),
            NodeL3Decision::Enforce { allow: true, .. }
        ));
    }
    let next = udp_from_a(&a, &b, 40000, 7000);
    let reason = NodeL3Reason::StateCapacity.drop_reason();
    dropped(&a, &mut b, &mut events, &next, reason).await?;

    // UDP flows idle out after 2 min; the full table sweeps them for the new flow.
    clock.advance(Duration::from_secs(121))?;
    delivered(&a, &mut b, &next).await?;
    assert_eq!(l3.gate.counters().state_capacity_denied, 1);
    Ok(())
}

// ── Modes ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn observe_leaves_the_verdict_to_the_acl_and_counts() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    let acl = acl(&l3)?;
    // Cross owner without a Grant: Enforce would deny.
    l3.gate
        .apply(config(&a, &b, &l3, NodeL3Mode::Observe, false, Vec::new()))?;

    acl.engine.load(AclPolicy::default())?;
    let first = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    dropped(&a, &mut b, &mut events, &first, reasons::DENIED).await?;
    acl.engine.load(accept_all())?;
    let packet = tcp4(v4(a.ip4, 40001), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;

    assert_eq!(l3.gate.counters().observed_denied, 2);
    let stats = l3.filter.stats();
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
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), true, |f| f).await?;
    let acl = acl(&l3)?;
    acl.engine.load(AclPolicy::default())?;
    enforce(&a, &b, &l3, true, Vec::new())?;
    let packet = tcp4(v4(a.ip4, 40000), v4(b.ip4, SSH), SYN);
    delivered(&a, &mut b, &packet).await?;

    let stats = l3.filter.stats();
    assert_eq!((stats.gate_accepted, stats.passed_to_acl), (1, 0));
    assert_eq!(acl.filter.stats().denied, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disabled_and_withdrawn_snapshots_leave_the_verdict_to_the_acl() -> TestResult {
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    let acl = acl(&l3)?;
    acl.engine.load(accept_all())?;
    let (a_ip, b_ip) = (a.ip4, b.ip4);
    let packet = |port| tcp4(v4(a_ip, port), v4(b_ip, SSH), SYN);
    let no_grant = NodeL3Reason::NoGrant.drop_reason();

    // Without a snapshot the gate is legacy.
    delivered(&a, &mut b, &packet(40000)).await?;
    // Enforce without a marked projection, so withdrawal leaves no pending marker.
    let mut snapshot = config(&a, &b, &l3, NodeL3Mode::Enforce, false, Vec::new());
    l3.gate.apply(snapshot.clone())?;
    dropped(&a, &mut b, &mut events, &packet(40001), no_grant).await?;

    // An explicit Disabled snapshot withdraws the Network.
    snapshot.generation = 2;
    snapshot.mode = NodeL3Mode::Disabled;
    l3.gate.apply(snapshot.clone())?;
    delivered(&a, &mut b, &packet(40002)).await?;
    acl.engine.load(AclPolicy::default())?;
    dropped(&a, &mut b, &mut events, &packet(40003), reasons::DENIED).await?;

    // Enforce again, then the source is withdrawn.
    snapshot.generation = 3;
    snapshot.mode = NodeL3Mode::Enforce;
    l3.gate.apply(snapshot)?;
    dropped(&a, &mut b, &mut events, &packet(40004), no_grant).await?;
    assert_eq!(l3.gate.withdraw_source(SOURCE)?, 1);
    dropped(&a, &mut b, &mut events, &packet(40005), reasons::DENIED).await?;

    let stats = l3.filter.stats();
    assert_eq!((stats.gate_denied, stats.passed_to_acl), (2, 4));
    Ok(())
}

// ── ICMP errors ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn icmp_errors_pass_only_for_their_flow() -> TestResult {
    let (mut a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f).await?;
    let mut events = b.subscribe().await?;
    enforce(&a, &b, &l3, false, vec![node_grant("node-b", "node-a")])?;
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
    let reason = NodeL3Reason::ReverseNewFlow.drop_reason();
    dropped(&a, &mut b, &mut events, &unrelated, reason).await?;
    assert_eq!(l3.filter.stats().gate_denied, 1);
    Ok(())
}

// ── Divert ───────────────────────────────────────────────────────────────────

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

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_gateway_return_is_diverted_to_the_consumer() -> TestResult {
    let queue = Queue::new(1);
    let sink = queue.clone();
    let (a, mut b, l3) = l3_pair(NodeL3Gate::new(MACHINE), false, |f| f.with_divert(sink)).await?;
    let mut events = b.subscribe().await?;
    // `b` binds no Node; `a` is the gateway carrier `gw-1` for `GATEWAY_TARGET`.
    let mut snapshot = config(&a, &b, &l3, NodeL3Mode::Enforce, false, Vec::new());
    snapshot.bindings.clear();
    snapshot.services.clear();
    l3.gate.apply(snapshot)?;
    l3.gate.replace_transport_projection(&NodeL3Transport {
        local_ip: b.ip4,
        peers: vec![NodeL3TransportPeer {
            public_key: l3.a_key,
            allowed_ips: vec![format!("{GATEWAY_TARGET}/32").parse()?],
            gateway_id: Some("gw-1".to_owned()),
            relayed: false,
            node_l3_policy: None,
        }],
    })?;
    let reply = udp(v4(GATEWAY_TARGET, 19999), v4(b.ip4, 49152), b"reply");

    a.send(&reply).await?;
    b.expect_no_delivery().await?;
    events
        .expect_none(|e| matches!(e, Event::Dropped { .. }))
        .await?;
    let peer_a = b.peer_of(&a).await?;
    {
        let taken = queue.taken();
        let [(peer, candidate)] = taken.as_slice() else {
            return Err(format!("{} candidates", taken.len()).into());
        };
        assert_eq!(*peer, peer_a);
        assert_eq!(candidate.packet(), reply.as_slice());
        assert_eq!(candidate.authority().gateway_id(), "gw-1");
        assert!(
            l3.gate
                .gateway_consumer_authority_current(candidate.authority())
        );
    }

    // The sink is full: the next return is dropped.
    let reason = NodeL3Reason::SourceBinding.drop_reason();
    dropped(&a, &mut b, &mut events, &reply, reason).await?;
    let stats = l3.filter.stats();
    assert_eq!(
        (stats.diverted, stats.divert_rejected, stats.gate_denied),
        (1, 1, 1)
    );
    Ok(())
}

// ── Outbound ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn outbound_to_a_node_without_a_grant_is_dropped_by_the_gate() -> TestResult {
    let (mut a, b, l3) = l3_pair(NodeL3Gate::new(MACHINE), true, |f| f).await?;
    let mut events = b.subscribe().await?;
    acl(&l3)?.engine.load(accept_all())?;
    // Only `a` may open flows to `b`.
    enforce(&a, &b, &l3, false, vec![node_grant("node-a", "node-b")])?;
    let packet = tcp4(v4(b.ip4, 5000), v4(a.ip4, SSH), SYN);
    let reason = NodeL3Reason::NoGrant.drop_reason();
    dropped(&b, &mut a, &mut events, &packet, reason).await?;

    let stats = l3.filter.stats();
    assert_eq!((stats.gate_denied, stats.passed_to_acl), (1, 0));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_acl_outbound_runs_only_when_opted_in() -> TestResult {
    for opt_in in [false, true] {
        let (mut a, b, l3) = l3_pair(NodeL3Gate::new(MACHINE), true, |f| {
            f.with_acl_outbound(opt_in)
        })
        .await?;
        let mut events = b.subscribe().await?;
        // `a`'s namespace restricts outbound traffic to it to TCP 443.
        acl(&l3)?.engine.store_namespace(
            "nsd:a",
            NamespacePolicy {
                members: vec![NamespaceMember {
                    label: Label::from(A_LABEL),
                    addresses: vec![format!("{}/32", a.ip4).parse()?],
                }],
                outbound: Some(vec![OutboundRule {
                    proto: Some("tcp".to_owned()),
                    ports: "443".to_owned(),
                }]),
                ..NamespacePolicy::default()
            },
        )?;
        let ssh = tcp4(v4(b.ip4, 5000), v4(a.ip4, SSH), SYN);
        if opt_in {
            dropped(&b, &mut a, &mut events, &ssh, reasons::OUTBOUND).await?;
            let https = tcp4(v4(b.ip4, 5000), v4(a.ip4, 443), SYN);
            delivered(&b, &mut a, &https).await?;
            assert_eq!(l3.filter.stats().passed_to_acl, 2);
        } else {
            delivered(&b, &mut a, &ssh).await?;
            assert_eq!(l3.filter.stats().passed_to_acl, 0);
        }
    }
    Ok(())
}
