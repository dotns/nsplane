//! The ACL filters at engine level, over an in-memory channel transport: two nodes `a` and
//! `b`, where `b` runs an `AclFilter` (and in one test a `FlowTracker` after it) on its
//! packets and `a` runs no filter. The tests keep the shared `AclEngine`, the
//! `PeerIdentityMap` naming `a`'s principal and a clone of the filter for its counters, and
//! check deliveries, `Event::Dropped` reasons and the filter counters while policies change
//! under the running engines.
//!
//! The runtime's clock is paused except in the reply expiry test: the filter's reply table
//! keeps `std::time::Instant`s, so that test waits real time.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nsplane::{ChannelSink, ChannelSource, ChannelTransport, EngineBuilder, Event, TransportId};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclFilterConfig, AclPolicy, AclRule, AclTest, FlowKey,
    FlowStats, FlowTracker, PeerIdentityMap, SourceAssertion, TerminateBinding, reasons,
    wg_peer_anchor,
};
use nsplane_e2e::{Events, Node, Options, TestResult, introduce, payload, udp};
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{FiveTuple, protocol};

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// The port `a`'s packets come from.
const SRC_PORT: u16 = 40000;
/// A port the policies of the tests allow on `b`.
const ALLOWED: u16 = 7000;
/// A port no policy allows.
const DENIED: u16 = 7001;
/// TCP flags of a SYN and of a SYN-ACK.
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;

type AclNode = Node<ChannelTransport>;

/// The ACL state of `b` the tests keep.
struct Acl {
    engine: Arc<AclEngine>,
    identities: Arc<PeerIdentityMap>,
    filter: AclFilter,
}

/// Two peers linked like `channel_pair`, `b` with an `AclFilter` (no policy loaded yet)
/// followed by `tracker` if given. `a`'s principal is its WireGuard key.
async fn acl_pair(
    config: AclFilterConfig,
    tracker: Option<FlowTracker>,
) -> TestResult<(AclNode, AclNode, Acl)> {
    let engine = Arc::new(AclEngine::new());
    let identities = Arc::new(PeerIdentityMap::new());
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
        let builder: EngineBuilder<ChannelSource, ChannelSink> =
            builder.transport(link_b).filter(Box::new(b_filter));
        match tracker {
            Some(tracker) => builder.filter(Box::new(tracker)),
            None => builder,
        }
    })?;
    introduce(&a, &b, None).await?;
    identities.insert(
        b.peer_of(&a).await?,
        SourceAssertion::WgPeerKey {
            pubkey: a.public().to_bytes(),
        },
    );
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

/// An accept rule; `proto` `None` matches TCP and UDP.
fn rule(src: &str, dst: &str, proto: Option<&str>) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec![src.to_owned()],
        dst: vec![dst.to_owned()],
        proto: proto.map(str::to_owned),
    }
}

fn policy(acls: Vec<AclRule>) -> AclPolicy {
    AclPolicy {
        acls,
        ..AclPolicy::default()
    }
}

/// A policy allowing `a`'s key UDP to `b`'s IPv4 address on `port`.
fn udp_policy(a: &AclNode, b: &AclNode, port: u16) -> AclPolicy {
    let src = wg_peer_anchor(&a.public().to_bytes());
    policy(vec![rule(&src, &format!("{}:{port}", b.ip4), Some("udp"))])
}

fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

/// An IP packet from `src` to `dst` carrying `segment` of `proto`; IPv4 with DF set.
fn ip(src: IpAddr, dst: IpAddr, proto: u8, segment: &[u8]) -> TestResult<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ip4(s, d, proto, 0, 0x4000, segment),
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut packet = vec![0x60, 0, 0, 0];
            packet.extend_from_slice(&u16::try_from(segment.len())?.to_be_bytes());
            packet.extend_from_slice(&[proto, 64]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            packet.extend_from_slice(segment);
            Ok(packet)
        }
        _ => Err("mixed IP versions".into()),
    }
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

/// A TCP segment without options or payload from `src` to `dst`, with a valid checksum.
fn tcp(src: SocketAddr, dst: SocketAddr, flags: u8) -> TestResult<Vec<u8>> {
    let mut segment = Vec::with_capacity(20);
    segment.extend_from_slice(&src.port().to_be_bytes());
    segment.extend_from_slice(&dst.port().to_be_bytes());
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.extend_from_slice(&u32::from(flags & 0x10 != 0).to_be_bytes());
    segment.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    let sum = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => transport_checksum_v4(s, d, protocol::TCP, &segment),
        (IpAddr::V6(s), IpAddr::V6(d)) => transport_checksum_v6(s, d, protocol::TCP, &segment),
        _ => return Err("mixed IP versions".into()),
    };
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    ip(src.ip(), dst.ip(), protocol::TCP, &segment)
}

/// A UDP datagram from `src` to `dst` split into two IPv4 fragments with identification
/// `id`: the first carries the UDP header and 8 payload bytes, the second the rest.
fn udp4_fragments(
    src: SocketAddr,
    dst: SocketAddr,
    id: u16,
    data: &[u8],
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        return Err("IPv4 only".into());
    };
    let whole = udp(src, dst, data);
    let (first, rest) = whole[20..].split_at(16);
    let more_fragments = 0x2000;
    Ok((
        ip4(s, d, protocol::UDP, id, more_fragments, first)?,
        ip4(s, d, protocol::UDP, id, 16 / 8, rest)?,
    ))
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
async fn policy_allows_and_denies_by_key_and_cidr_principals() -> TestResult {
    let (mut a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    let src = wg_peer_anchor(&a.public().to_bytes());
    acl.engine.load(policy(vec![
        rule(&src, &format!("{}:{ALLOWED}", b.ip4), Some("udp")),
        rule(&src, &format!("{}:{ALLOWED}", b.ip6), Some("udp")),
    ]))?;

    for (from, to) in [
        (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4)),
        (IpAddr::V6(a.ip6), IpAddr::V6(b.ip6)),
    ] {
        let a_end = SocketAddr::new(from, SRC_PORT);
        delivered(&a, &mut b, &udp(a_end, SocketAddr::new(to, ALLOWED), b"in")).await?;
        // `b`'s reply is outbound for its filter and `a` has none.
        delivered(
            &b,
            &mut a,
            &udp(SocketAddr::new(to, ALLOWED), a_end, b"out"),
        )
        .await?;
        let denied = udp(a_end, SocketAddr::new(to, DENIED), b"in");
        dropped(&a, &mut b, &mut events, &denied, reasons::DENIED).await?;
    }
    assert_eq!(b.drops(reasons::DENIED).await?, 2);

    // A terminate binding carries `a`'s tunnel IP, which CIDR rules match; the key rules
    // no longer match it. A new source port keeps `b`'s replies above from allowing it.
    let peer_a = b.peer_of(&a).await?;
    acl.identities.insert(
        peer_a,
        SourceAssertion::Terminate {
            binding: TerminateBinding {
                ip: Some(IpAddr::V4(a.ip4)),
                anchor: "tunnel-a".to_owned(),
            },
        },
    );
    let to_allowed = udp(v4(a.ip4, SRC_PORT + 1), v4(b.ip4, ALLOWED), b"in");
    dropped(&a, &mut b, &mut events, &to_allowed, reasons::DENIED).await?;
    acl.engine.load(policy(vec![rule(
        &format!("{}/32", a.ip4),
        &format!("{}:{ALLOWED}", b.ip4),
        Some("udp"),
    )]))?;
    delivered(&a, &mut b, &to_allowed).await?;
    let to_denied = udp(v4(a.ip4, SRC_PORT + 1), v4(b.ip4, DENIED), b"in");
    dropped(&a, &mut b, &mut events, &to_denied, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (3, 4));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn tcp_rules_match_tcp_only() -> TestResult {
    let (a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    let src = wg_peer_anchor(&a.public().to_bytes());
    acl.engine.load(policy(vec![
        rule(&src, &format!("{}:{ALLOWED}", b.ip4), Some("tcp")),
        rule(&src, &format!("{}:{ALLOWED}", b.ip6), Some("tcp")),
    ]))?;

    for (from, to) in [
        (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4)),
        (IpAddr::V6(a.ip6), IpAddr::V6(b.ip6)),
    ] {
        let a_end = SocketAddr::new(from, SRC_PORT);
        let allowed = SocketAddr::new(to, ALLOWED);
        delivered(&a, &mut b, &tcp(a_end, allowed, SYN)?).await?;
        let denied = tcp(a_end, SocketAddr::new(to, DENIED), SYN)?;
        dropped(&a, &mut b, &mut events, &denied, reasons::DENIED).await?;
        // The tcp-only rule rejects UDP to the same port.
        let udp_allowed_port = udp(a_end, allowed, b"udp");
        dropped(&a, &mut b, &mut events, &udp_allowed_port, reasons::DENIED).await?;
    }

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (2, 4));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reload_swaps_the_policy_and_a_rejected_reload_keeps_it() -> TestResult {
    let (a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    let (p1, p2) = (ALLOWED, ALLOWED + 10);
    let to_p1 = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, p1), b"p1");
    let to_p2 = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, p2), b"p2");

    acl.engine.load(udp_policy(&a, &b, p1))?;
    delivered(&a, &mut b, &to_p1).await?;
    dropped(&a, &mut b, &mut events, &to_p2, reasons::DENIED).await?;

    acl.engine.load(udp_policy(&a, &b, p2))?;
    dropped(&a, &mut b, &mut events, &to_p1, reasons::DENIED).await?;
    delivered(&a, &mut b, &to_p2).await?;

    // A policy whose built-in test fails is rejected; `p2` stays open.
    let mut failing = udp_policy(&a, &b, p1);
    failing.tests.push(AclTest {
        src: a.ip4.to_string(),
        dst: format!("{}:{p1}", b.ip4),
        proto: Some("udp".to_owned()),
        allow: true,
    });
    if acl.engine.load(failing).is_ok() {
        return Err("a policy failing its tests was loaded".into());
    }
    delivered(&a, &mut b, &to_p2).await?;
    dropped(&a, &mut b, &mut events, &to_p1, reasons::DENIED).await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fail_closed_until_a_policy_loads_and_unknown_peers_are_dropped() -> TestResult {
    let (a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    let packet = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, ALLOWED), b"in");

    dropped(&a, &mut b, &mut events, &packet, reasons::NO_POLICY).await?;
    acl.engine.load(udp_policy(&a, &b, ALLOWED))?;
    delivered(&a, &mut b, &packet).await?;

    acl.identities.remove(b.peer_of(&a).await?);
    dropped(&a, &mut b, &mut events, &packet, reasons::UNKNOWN_PEER).await?;

    let stats = acl.filter.stats();
    assert_eq!(
        (stats.no_policy, stats.accepted, stats.unknown_peer),
        (1, 1, 1)
    );
    assert_eq!(b.drops(reasons::NO_POLICY).await?, 1);
    assert_eq!(b.drops(reasons::UNKNOWN_PEER).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fragments_follow_their_first_fragment() -> TestResult {
    let (a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(udp_policy(&a, &b, ALLOWED))?;
    let data = payload(64);
    let a_end = v4(a.ip4, SRC_PORT);

    let (first, second) = udp4_fragments(a_end, v4(b.ip4, ALLOWED), 1, &data)?;
    delivered(&a, &mut b, &first).await?;
    delivered(&a, &mut b, &second).await?;

    let (first, second) = udp4_fragments(a_end, v4(b.ip4, DENIED), 2, &data)?;
    dropped(&a, &mut b, &mut events, &first, reasons::DENIED).await?;
    dropped(&a, &mut b, &mut events, &second, reasons::DENIED).await?;

    let (_, orphan) = udp4_fragments(a_end, v4(b.ip4, ALLOWED), 3, &data)?;
    dropped(&a, &mut b, &mut events, &orphan, reasons::FRAGMENT).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied, stats.fragment), (2, 2, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn replies_to_flows_b_opened_pass_a_deny_all_policy() -> TestResult {
    let (mut a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(AclPolicy::default())?;
    let (b_end, a_end) = (v4(b.ip4, 5000), v4(a.ip4, 6000));
    let stranger = v4(a.ip4, 6001);

    delivered(&b, &mut a, &udp(b_end, a_end, b"request")).await?;
    delivered(&a, &mut b, &udp(a_end, b_end, b"reply")).await?;
    let unsolicited = udp(stranger, b_end, b"unsolicited");
    dropped(&a, &mut b, &mut events, &unsolicited, reasons::DENIED).await?;

    delivered(&b, &mut a, &tcp(b_end, a_end, SYN)?).await?;
    delivered(&a, &mut b, &tcp(a_end, b_end, SYN_ACK)?).await?;
    let unsolicited = tcp(stranger, b_end, SYN_ACK)?;
    dropped(&a, &mut b, &mut events, &unsolicited, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.replies, stats.accepted, stats.denied), (2, 0, 2));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn replies_are_dropped_without_a_policy() -> TestResult {
    let (mut a, mut b, acl) = acl_pair(AclFilterConfig::default(), None).await?;
    let mut events = b.subscribe().await?;
    let (b_end, a_end) = (v4(b.ip4, 5000), v4(a.ip4, 6000));

    delivered(&b, &mut a, &udp(b_end, a_end, b"request")).await?;
    let reply = udp(a_end, b_end, b"reply");
    dropped(&a, &mut b, &mut events, &reply, reasons::NO_POLICY).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.replies, stats.no_policy), (0, 1));
    Ok(())
}

/// Real time: the reply table uses `std::time::Instant`.
#[tokio::test(flavor = "current_thread")]
async fn reply_allowances_expire_when_idle() -> TestResult {
    let config = AclFilterConfig {
        reply_idle_timeout: Duration::from_millis(200),
        ..AclFilterConfig::default()
    };
    let (mut a, mut b, acl) = acl_pair(config, None).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(AclPolicy::default())?;
    let (b_end, a_end) = (v4(b.ip4, 5000), v4(a.ip4, 6000));
    let reply = udp(a_end, b_end, b"reply");

    delivered(&b, &mut a, &udp(b_end, a_end, b"request")).await?;
    delivered(&a, &mut b, &reply).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    dropped(&a, &mut b, &mut events, &reply, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!(
        (stats.replies, stats.reply_expired, stats.denied),
        (1, 1, 1)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn flow_tracker_counts_flows_the_acl_lets_through() -> TestResult {
    let tracker = FlowTracker::new(2);
    let (mut a, mut b, acl) = acl_pair(AclFilterConfig::default(), Some(tracker.clone())).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(udp_policy(&a, &b, ALLOWED))?;
    let (a_end, b_end) = (v4(a.ip4, SRC_PORT), v4(b.ip4, ALLOWED));
    let peer_a = b.peer_of(&a).await?;
    let flow = |src: SocketAddr| FlowKey {
        peer: peer_a,
        tuple: FiveTuple {
            src: src.ip(),
            dst: b_end.ip(),
            protocol: protocol::UDP,
            src_port: src.port(),
            dst_port: b_end.port(),
        },
    };

    let mut expected = FlowStats::default();
    for len in [10, 100, 1000] {
        let packet = udp(a_end, b_end, &payload(len));
        delivered(&a, &mut b, &packet).await?;
        expected.rx_packets += 1;
        expected.rx_bytes += u64::try_from(packet.len())?;
    }
    for len in [20, 200] {
        let packet = udp(b_end, a_end, &payload(len));
        delivered(&b, &mut a, &packet).await?;
        expected.tx_packets += 1;
        expected.tx_bytes += u64::try_from(packet.len())?;
    }
    assert_eq!(tracker.flow(&flow(a_end)), Some(expected));

    // The ACL filter runs first and drops the denied flow before the tracker sees it.
    let denied = udp(a_end, v4(b.ip4, DENIED), b"denied");
    dropped(&a, &mut b, &mut events, &denied, reasons::DENIED).await?;
    assert_eq!((tracker.len(), tracker.evictions()), (1, 0));

    // A third flow in a table of two evicts the least recently seen one.
    for port in [SRC_PORT + 1, SRC_PORT + 2] {
        delivered(&a, &mut b, &udp(v4(a.ip4, port), b_end, b"new")).await?;
    }
    assert_eq!((tracker.len(), tracker.evictions()), (2, 1));
    assert_eq!(tracker.flow(&flow(a_end)), None);
    assert!(tracker.flow(&flow(v4(a.ip4, SRC_PORT + 2))).is_some());
    Ok(())
}
