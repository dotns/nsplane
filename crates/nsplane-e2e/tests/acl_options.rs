//! The ACL filter with its stateless options set explicitly in `AclFilterConfig` (no reply
//! allowances, allow-only IPv4 fragments, the `accept_to_local` and `accept_icmp_echo_reply`
//! bypasses, IPv6 accepted unevaluated), at engine level over an in-memory channel transport:
//! two nodes `a` and `b`, where `b` runs an `AclFilter` with these options on its packets and
//! `a` runs no filter. The tests keep the shared `AclEngine`, the `PeerLabelMap` giving `a`'s
//! labels and a clone of the filter for its counters, and check deliveries and
//! `Event::Dropped` reasons for peers judged by their packets' source address (a prefix rule)
//! and by their key label, the allow-only fragment gate, the bypass options, the absence of
//! reply allowances, IPv6 passing unevaluated and rule updates under traffic.
//!
//! The runtime's clock is paused and the `AclEngine` reads tokio's clock, so the fragment
//! TTL elapses with `tokio::time::advance`. The options are built without a local address
//! (every packet to `b` would bypass the rules) except in the bypass test.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nsplane::{AllowedIp, ChannelTransport, Event, TransportId};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, FragmentMode, IpNet, Ipv6Mode, Label, LabelSet,
    PeerLabelMap, PortSet, ProtocolMatch, Rule, RuleSet, reasons,
};
use nsplane_e2e::{Events, Node, Options, TestResult, icmp, introduce, payload, tcp, udp};
use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::protocol;

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// The port `a`'s packets come from.
const SRC_PORT: u16 = 40000;
/// A port the rules of the tests allow on `b`.
const ALLOWED: u16 = 7000;
/// A port no rule allows.
const DENIED: u16 = 7001;
/// ICMP echo reply and echo request (type, code).
const ECHO_REPLY: (u8, u8) = (0, 0);
const ECHO_REQUEST: (u8, u8) = (8, 0);
/// How long an accepted first fragment admits its later fragments.
const FRAGMENT_TTL: Duration = Duration::from_secs(15);
/// Just under [`FRAGMENT_TTL`].
const UNDER_TTL: Duration = Duration::from_secs(14);
/// A key that is not `a`'s.
const OTHER_KEY: [u8; 32] = [0xaa; 32];
/// A label of a peer judged by its packets' source address.
const ADDRESS: &str = "addr";

type AclNode = Node<ChannelTransport>;

/// The ACL state of `b` the tests keep.
struct Acl {
    engine: Arc<AclEngine>,
    identities: Arc<PeerLabelMap>,
    filter: AclFilter,
}

/// The label of a peer known by its key: `key:` and the lowercase hex of `key`.
fn key_label(key: &[u8; 32]) -> Label {
    Label::from(key.iter().fold(String::from("key:"), |mut text, b| {
        let _ = write!(text, "{b:02x}");
        text
    }))
}

/// Two peers linked like `channel_pair`, `b` with an `AclFilter` configured by `config`
/// (no rules installed yet, no identity for `a` yet) whose engine reads tokio's clock.
async fn acl_pair(config: AclFilterConfig) -> TestResult<(AclNode, AclNode, Acl)> {
    let engine = Arc::new(AclEngine::with_clock(|| {
        tokio::time::Instant::now().into_std()
    }));
    let identities = Arc::new(PeerLabelMap::new());
    let filter = AclFilter::with_config(Arc::clone(&engine), Arc::clone(&identities), config);

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
    Ok((
        a,
        b,
        Acl {
            engine,
            identities,
            filter,
        },
    ))
}

/// [`acl_pair`] with `a` known to `b`'s filter by the label of its WireGuard key.
async fn key_pair(config: AclFilterConfig) -> TestResult<(AclNode, AclNode, Acl)> {
    let (a, b, acl) = acl_pair(config).await?;
    acl.identities.insert(
        b.peer_of(&a).await?,
        LabelSet::new([key_label(&a.public().to_bytes())]),
    );
    Ok((a, b, acl))
}

/// [`acl_pair`] with `a` carrying the address label on `b`'s filter, and `a`'s allowed IPs
/// on `b` widened by `10.1.0.0/24`, the subnet behind `a` its packets come from.
async fn by_source_pair(config: AclFilterConfig) -> TestResult<(AclNode, AclNode, Acl)> {
    let (a, b, acl) = acl_pair(config).await?;
    let mut to_a = a.as_peer(b.path.transport);
    to_a.allowed_ips.push(AllowedIp {
        addr: IpAddr::V4(gateway(0)),
        cidr: 24,
    });
    b.handle.add_or_update_peer(to_a).await?;
    acl.identities
        .insert(b.peer_of(&a).await?, LabelSet::new([Label::from(ADDRESS)]));
    Ok((a, b, acl))
}

/// Host `host` of the subnet behind `a` in [`by_source_pair`].
const fn gateway(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 1, 0, host)
}

/// The stateless options with `local` in `accept_to_local`: no reply allowances, protocols
/// other than TCP and UDP dropped, allow-only fragments ([`FRAGMENT_TTL`], 4096 entries),
/// echo replies and IPv6 accepted unevaluated.
fn options_with(local: Option<Ipv4Addr>) -> AclFilterConfig {
    AclFilterConfig {
        stateful_replies: false,
        allow_other_protocols: false,
        fragments: FragmentMode::AllowOnly {
            ttl: FRAGMENT_TTL,
            capacity: 4096,
        },
        accept_to_local: local,
        accept_icmp_echo_reply: true,
        ipv6: Ipv6Mode::Accept,
        ..AclFilterConfig::default()
    }
}

/// [`options_with`] without a local address.
fn options() -> AclFilterConfig {
    options_with(None)
}

/// The host network of `ip`.
fn host(ip: Ipv4Addr) -> TestResult<IpNet> {
    Ok(ip.to_string().parse()?)
}

/// A rule accepting UDP to `dst`'s address and port, from any source.
fn udp_to(dst: SocketAddr) -> TestResult<Rule> {
    let IpAddr::V4(ip) = dst.ip() else {
        return Err("IPv4 only".into());
    };
    Ok(
        Rule::new("udp", vec![ProtocolMatch::Udp(PortSet::single(dst.port()))])
            .with_destinations([host(ip)?]),
    )
}

/// Rules allowing UDP from the source address `src` to `b`'s IPv4 address on `port`.
fn from_source(src: Ipv4Addr, b: &AclNode, port: u16) -> TestResult<RuleSet> {
    Ok(RuleSet::new([
        udp_to(v4(b.ip4, port))?.with_sources([host(src)?])
    ])?)
}

/// Rules allowing UDP from sources labelled `label` to `b`'s IPv4 address on `port`.
fn from_label(label: Label, b: &AclNode, port: u16) -> TestResult<RuleSet> {
    Ok(RuleSet::new([
        udp_to(v4(b.ip4, port))?.with_labels([label])
    ])?)
}

const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

/// An IPv4 packet with identification `id` and the flags/fragment offset field `fragment`.
fn ip4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    fragment: u16,
    data: &[u8],
) -> TestResult<Vec<u8>> {
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&u16::try_from(20 + data.len())?.to_be_bytes());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&fragment.to_be_bytes());
    packet.extend_from_slice(&[64, proto, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let sum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(data);
    Ok(packet)
}

/// A UDP datagram from `src` to `dst` (at least 24 bytes of `data`) split into three IPv4
/// fragments with identification `id`: the first carries the UDP header and 8 payload
/// bytes, the second the next 16 bytes, the third the rest.
fn udp4_fragments(
    src: SocketAddr,
    dst: SocketAddr,
    id: u16,
    data: &[u8],
) -> TestResult<[Vec<u8>; 3]> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        return Err("IPv4 only".into());
    };
    let whole = udp(src, dst, data);
    let segment = &whole[20..];
    let more_fragments = 0x2000;
    Ok([
        ip4(s, d, protocol::UDP, id, more_fragments, &segment[..16])?,
        ip4(
            s,
            d,
            protocol::UDP,
            id,
            more_fragments | (16 / 8),
            &segment[16..32],
        )?,
        ip4(s, d, protocol::UDP, id, 32 / 8, &segment[32..])?,
    ])
}

/// An ICMP echo message of `kind` from `src` to `dst`.
fn echo(src: Ipv4Addr, dst: Ipv4Addr, kind: (u8, u8)) -> Vec<u8> {
    icmp(
        IpAddr::V4(src),
        IpAddr::V4(dst),
        kind,
        [0, 1, 0, 1],
        b"ping",
    )
}

/// Sends `packet` from `from` and checks that `to` delivers it unchanged.
async fn delivered(from: &AclNode, to: &mut AclNode, packet: &[u8]) -> TestResult {
    from.send(packet).await?;
    let (_, got) = to.expect_delivery().await?;
    if got != packet {
        return Err("packet changed in transit".into());
    }
    Ok(())
}

/// Sends `packet` from `from` and checks that `to` drops it with `reason`.
async fn dropped(
    from: &AclNode,
    to: &mut AclNode,
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

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn prefix_rules_judge_the_packet_sources() -> TestResult {
    let (a, mut b, acl) = by_source_pair(options()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.install(from_source(gateway(1), &b, ALLOWED)?);
    let to_b = v4(b.ip4, ALLOWED);

    delivered(&a, &mut b, &udp(v4(gateway(1), SRC_PORT), to_b, b"one")).await?;
    let from_two = udp(v4(gateway(2), SRC_PORT), to_b, b"two");
    dropped(&a, &mut b, &mut events, &from_two, reasons::DENIED).await?;
    // `a`'s own tunnel address is just another source; its key plays no part.
    let from_a = udp(v4(a.ip4, SRC_PORT), to_b, b"a");
    dropped(&a, &mut b, &mut events, &from_a, reasons::DENIED).await?;
    // Each source keeps its own verdict when they interleave.
    delivered(&a, &mut b, &udp(v4(gateway(1), SRC_PORT), to_b, b"one")).await?;
    dropped(&a, &mut b, &mut events, &from_two, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (2, 3));
    assert_eq!(b.drops(reasons::DENIED).await?, 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn key_labels_follow_identity_changes() -> TestResult {
    let (a, mut b, acl) = key_pair(options()).await?;
    let mut events = b.subscribe().await?;
    let packet = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, ALLOWED), b"key");
    let a_key = key_label(&a.public().to_bytes());

    acl.engine.install(from_label(a_key, &b, ALLOWED)?);
    delivered(&a, &mut b, &packet).await?;
    acl.engine
        .install(from_label(key_label(&OTHER_KEY), &b, ALLOWED)?);
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;

    // The rules stay; `a`'s identity switches to the other key and back.
    let peer_a = b.peer_of(&a).await?;
    acl.identities
        .insert(peer_a, LabelSet::new([key_label(&OTHER_KEY)]));
    delivered(&a, &mut b, &packet).await?;
    acl.identities
        .insert(peer_a, LabelSet::new([key_label(&a.public().to_bytes())]));
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;
    // With the address label only, the key rule no longer matches.
    acl.identities
        .insert(peer_a, LabelSet::new([Label::from(ADDRESS)]));
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (2, 3));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fragments_follow_an_accepted_first_fragment_within_the_ttl() -> TestResult {
    let (a, mut b, acl) = key_pair(options()).await?;
    let mut events = b.subscribe().await?;
    acl.engine
        .install(from_label(key_label(&a.public().to_bytes()), &b, ALLOWED)?);
    let data = payload(64);
    let a_end = v4(a.ip4, SRC_PORT);
    let (allowed, denied) = (v4(b.ip4, ALLOWED), v4(b.ip4, DENIED));

    // An allowed datagram arrives whole.
    for fragment in udp4_fragments(a_end, allowed, 1, &data)? {
        delivered(&a, &mut b, &fragment).await?;
    }

    // Only accepted first fragments are remembered.
    let [first, second, third] = udp4_fragments(a_end, denied, 2, &data)?;
    dropped(&a, &mut b, &mut events, &first, reasons::DENIED).await?;
    dropped(&a, &mut b, &mut events, &second, reasons::FRAGMENT).await?;
    dropped(&a, &mut b, &mut events, &third, reasons::FRAGMENT).await?;

    // A continuation before its first fragment is dropped, not held.
    let [first, second, third] = udp4_fragments(a_end, allowed, 3, &data)?;
    dropped(&a, &mut b, &mut events, &second, reasons::FRAGMENT).await?;
    delivered(&a, &mut b, &first).await?;
    delivered(&a, &mut b, &third).await?;

    // The first fragment admits its continuations for the TTL only.
    let [first, second, third] = udp4_fragments(a_end, allowed, 4, &data)?;
    delivered(&a, &mut b, &first).await?;
    tokio::time::advance(UNDER_TTL).await;
    delivered(&a, &mut b, &second).await?;
    tokio::time::advance(Duration::from_secs(2)).await;
    dropped(&a, &mut b, &mut events, &third, reasons::FRAGMENT).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied, stats.fragment), (7, 1, 4));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bypass_options_skip_the_rules_only_when_set() -> TestResult {
    // `accept_to_local`: packets to `b`'s address pass with and without rules, and
    // packets to its other address do not (IPv6 evaluated, so the option alone decides).
    let config = AclFilterConfig {
        ipv6: Ipv6Mode::Evaluate,
        ..options_with(Some(Ipv4Addr::new(10, 0, 0, 2)))
    };
    let (a, mut b, acl) = key_pair(config).await?;
    let mut events = b.subscribe().await?;
    let to_local = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, DENIED), b"local");
    delivered(&a, &mut b, &to_local).await?;
    acl.engine.install(RuleSet::empty());
    delivered(&a, &mut b, &to_local).await?;
    let to_v6 = udp(
        SocketAddr::new(IpAddr::V6(a.ip6), SRC_PORT),
        SocketAddr::new(IpAddr::V6(b.ip6), DENIED),
        b"v6",
    );
    dropped(&a, &mut b, &mut events, &to_v6, reasons::DENIED).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.bypassed, stats.denied), (2, 1));

    // `accept_icmp_echo_reply`: an echo reply passes an empty rule set, a request does not.
    let (a, mut b, acl) = key_pair(options()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.install(RuleSet::empty());
    let reply = echo(a.ip4, b.ip4, ECHO_REPLY);
    delivered(&a, &mut b, &reply).await?;
    let request = echo(a.ip4, b.ip4, ECHO_REQUEST);
    dropped(&a, &mut b, &mut events, &request, reasons::PROTOCOL).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.bypassed, stats.protocol), (1, 1));

    // Both off: the same packets are judged by the rules.
    let config = AclFilterConfig {
        accept_to_local: None,
        accept_icmp_echo_reply: false,
        ..options()
    };
    let (a, mut b, acl) = key_pair(config).await?;
    let mut events = b.subscribe().await?;
    acl.engine.install(RuleSet::empty());
    dropped(&a, &mut b, &mut events, &to_local, reasons::DENIED).await?;
    let reply = echo(a.ip4, b.ip4, ECHO_REPLY);
    dropped(&a, &mut b, &mut events, &reply, reasons::PROTOCOL).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.bypassed, stats.denied, stats.protocol), (0, 1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn ipv6_passes_unevaluated_with_ipv6_accept_only() -> TestResult {
    let syn = 0x02;
    let (a, mut b, acl) = key_pair(options()).await?;
    acl.engine.install(RuleSet::empty());
    let packet = tcp(
        SocketAddr::new(IpAddr::V6(a.ip6), SRC_PORT),
        SocketAddr::new(IpAddr::V6(b.ip6), DENIED),
        syn,
        (1, 0),
        b"v6",
    );
    delivered(&a, &mut b, &packet).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.ipv6_accepted, stats.accepted), (1, 0));

    // The default config judges the same packet by the rules.
    let (a, mut b, acl) = key_pair(AclFilterConfig::default()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.install(RuleSet::empty());
    let packet = tcp(
        SocketAddr::new(IpAddr::V6(a.ip6), SRC_PORT),
        SocketAddr::new(IpAddr::V6(b.ip6), DENIED),
        syn,
        (1, 0),
        b"v6",
    );
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.ipv6_accepted, stats.denied), (0, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn replies_are_judged_by_the_rules_without_stateful_replies() -> TestResult {
    let (b_end, a_end) = (
        v4(Ipv4Addr::new(10, 0, 0, 2), 5000),
        v4(Ipv4Addr::new(10, 0, 0, 1), 6000),
    );
    let request = udp(b_end, a_end, b"request");
    let reply = udp(a_end, b_end, b"reply");

    // Control: the default config lets the reply through an empty rule set.
    let (mut a, mut b, acl) = key_pair(AclFilterConfig::default()).await?;
    acl.engine.install(RuleSet::empty());
    delivered(&b, &mut a, &request).await?;
    delivered(&a, &mut b, &reply).await?;
    assert_eq!(acl.filter.stats().replies, 1);

    let (mut a, mut b, acl) = key_pair(options()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.install(RuleSet::empty());
    delivered(&b, &mut a, &request).await?;
    dropped(&a, &mut b, &mut events, &reply, reasons::DENIED).await?;
    // A rule accepting the reply's flow lets it in as a new flow.
    let rule = udp_to(b_end)?.with_labels([key_label(&a.public().to_bytes())]);
    acl.engine.install(RuleSet::new([rule])?);
    delivered(&a, &mut b, &reply).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.replies, stats.accepted, stats.denied), (0, 1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn rule_updates_apply_to_the_next_packet_under_traffic() -> TestResult {
    let (a, mut b, acl) = by_source_pair(options()).await?;
    let mut events = b.subscribe().await?;
    let sources = [gateway(1), gateway(2)];
    let to_b = v4(b.ip4, ALLOWED);
    let packet = |src: Ipv4Addr| udp(v4(src, SRC_PORT), to_b, b"traffic");

    // Each round lets one source in; both send before and after every install, so a
    // cached verdict of the previous rules would show.
    for round in 0..6 {
        let open = sources[round % 2];
        acl.engine.install(from_source(open, &b, ALLOWED)?);
        for _ in 0..3 {
            for src in sources {
                if src == open {
                    delivered(&a, &mut b, &packet(src)).await?;
                } else {
                    dropped(&a, &mut b, &mut events, &packet(src), reasons::DENIED).await?;
                }
            }
        }
    }

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (18, 18));
    Ok(())
}
