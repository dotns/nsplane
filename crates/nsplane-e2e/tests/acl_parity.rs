//! The ACL filter in the `crates/acl` mode (`AclFilterConfig::crates_acl`), at engine
//! level over an in-memory channel transport: two nodes `a` and `b`, where `b` runs an
//! `AclFilter` with that preset on its packets and `a` runs no filter. The tests keep the
//! shared `AclEngine`, the `PeerIdentityMap` naming `a`'s principals and a clone of the
//! filter for its counters, and check deliveries and `Event::Dropped` reasons for
//! by-source and relay-key principals, the allow-only fragment gate, the bypass flags,
//! the absence of reply allowances, IPv6 passing unevaluated and policy reloads under
//! traffic.
//!
//! The runtime's clock is paused and the `AclEngine` reads tokio's clock, so the fragment
//! TTL elapses with `tokio::time::advance`. The preset is built without a local address
//! (every packet to `b` would bypass the policy) except in the bypass test.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nsplane::{AllowedIp, ChannelTransport, Event, TransportId};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclFilterConfig, AclPolicy, AclRule, Ipv6Mode,
    PeerIdentityMap, SourceAssertion, reasons, wg_peer_anchor,
};
use nsplane_e2e::{Events, Node, Options, TestResult, icmp, introduce, payload, tcp, udp};
use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::protocol;

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// The port `a`'s packets come from.
const SRC_PORT: u16 = 40000;
/// A port the policies of the tests allow on `b`.
const ALLOWED: u16 = 7000;
/// A port no policy allows.
const DENIED: u16 = 7001;
/// ICMP echo reply and echo request (type, code).
const ECHO_REPLY: (u8, u8) = (0, 0);
const ECHO_REQUEST: (u8, u8) = (8, 0);
/// Just under the TTL of `FragmentMode::ALLOW_ONLY` (15 s).
const UNDER_TTL: Duration = Duration::from_secs(14);
/// A key that is not `a`'s.
const OTHER_KEY: [u8; 32] = [0xaa; 32];

type AclNode = Node<ChannelTransport>;

/// The ACL state of `b` the tests keep.
struct Acl {
    engine: Arc<AclEngine>,
    identities: Arc<PeerIdentityMap>,
    filter: AclFilter,
}

/// Two peers linked like `channel_pair`, `b` with an `AclFilter` configured by `config`
/// (no policy loaded yet, no identity for `a` yet) whose engine reads tokio's clock.
async fn acl_pair(config: AclFilterConfig) -> TestResult<(AclNode, AclNode, Acl)> {
    let engine = Arc::new(AclEngine::with_clock(|| {
        tokio::time::Instant::now().into_std()
    }));
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

/// [`acl_pair`] with `a` known to `b`'s filter by its WireGuard key, as a relay client.
async fn key_pair(config: AclFilterConfig) -> TestResult<(AclNode, AclNode, Acl)> {
    let (a, b, acl) = acl_pair(config).await?;
    acl.identities.insert(
        b.peer_of(&a).await?,
        SourceAssertion::WgPeerKey {
            pubkey: a.public().to_bytes(),
        },
    );
    Ok((a, b, acl))
}

/// [`acl_pair`] with `a` marked by source on `b`'s filter, and `a`'s allowed IPs on `b`
/// widened by `10.1.0.0/24`, the gateway subnet `a`'s packets come from.
async fn by_source_pair(config: AclFilterConfig) -> TestResult<(AclNode, AclNode, Acl)> {
    let (a, b, acl) = acl_pair(config).await?;
    let mut to_a = a.as_peer(b.path.transport);
    to_a.allowed_ips.push(AllowedIp {
        addr: IpAddr::V4(gateway(0)),
        cidr: 24,
    });
    b.handle.add_or_update_peer(to_a).await?;
    acl.identities.insert_by_source(b.peer_of(&a).await?);
    Ok((a, b, acl))
}

/// Host `host` of the subnet behind `a` in [`by_source_pair`].
const fn gateway(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 1, 0, host)
}

/// The `crates/acl` preset without a local address.
fn preset() -> AclFilterConfig {
    AclFilterConfig::crates_acl(None)
}

/// An accept rule for UDP.
fn rule(src: &str, dst: &str) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec![src.to_owned()],
        dst: vec![dst.to_owned()],
        proto: Some("udp".to_owned()),
    }
}

fn policy(acls: Vec<AclRule>) -> AclPolicy {
    AclPolicy {
        acls,
        ..AclPolicy::default()
    }
}

/// A policy allowing the principal `src` UDP to `b`'s IPv4 address on `port`.
fn udp_policy(src: &str, b: &AclNode, port: u16) -> AclPolicy {
    policy(vec![rule(src, &format!("{}:{port}", b.ip4))])
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
async fn by_source_principals_are_the_packet_sources() -> TestResult {
    let (a, mut b, acl) = by_source_pair(preset()).await?;
    let mut events = b.subscribe().await?;
    acl.engine
        .load(udp_policy(&format!("{}/32", gateway(1)), &b, ALLOWED))?;
    let to_b = v4(b.ip4, ALLOWED);

    delivered(&a, &mut b, &udp(v4(gateway(1), SRC_PORT), to_b, b"one")).await?;
    let from_two = udp(v4(gateway(2), SRC_PORT), to_b, b"two");
    dropped(&a, &mut b, &mut events, &from_two, reasons::DENIED).await?;
    // `a`'s own tunnel address is just another source; its key is no principal.
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
async fn relay_client_keys_are_principals_and_follow_identity_changes() -> TestResult {
    let (a, mut b, acl) = key_pair(preset()).await?;
    let mut events = b.subscribe().await?;
    let packet = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, ALLOWED), b"key");
    let a_key = wg_peer_anchor(&a.public().to_bytes());
    let other_key = wg_peer_anchor(&OTHER_KEY);

    acl.engine.load(udp_policy(&a_key, &b, ALLOWED))?;
    delivered(&a, &mut b, &packet).await?;
    acl.engine.load(udp_policy(&other_key, &b, ALLOWED))?;
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;

    // The policy stays; `a`'s identity switches to the other key and back.
    let peer_a = b.peer_of(&a).await?;
    acl.identities
        .insert(peer_a, SourceAssertion::WgPeerKey { pubkey: OTHER_KEY });
    delivered(&a, &mut b, &packet).await?;
    acl.identities.insert(
        peer_a,
        SourceAssertion::WgPeerKey {
            pubkey: a.public().to_bytes(),
        },
    );
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;
    // Marked by source, the principal is `a`'s tunnel address, which no rule names.
    acl.identities.insert_by_source(peer_a);
    dropped(&a, &mut b, &mut events, &packet, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (2, 3));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fragments_follow_an_accepted_first_fragment_within_the_ttl() -> TestResult {
    let (a, mut b, acl) = key_pair(preset()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(udp_policy(
        &wg_peer_anchor(&a.public().to_bytes()),
        &b,
        ALLOWED,
    ))?;
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
async fn bypass_flags_skip_the_policy_only_when_set() -> TestResult {
    // `accept_to_local`: packets to `b`'s address pass with and without a policy, and
    // packets to its other address do not (IPv6 evaluated, so the flag alone decides).
    let config = AclFilterConfig {
        ipv6: Ipv6Mode::Evaluate,
        ..AclFilterConfig::crates_acl(Some(Ipv4Addr::new(10, 0, 0, 2)))
    };
    let (a, mut b, acl) = key_pair(config).await?;
    let mut events = b.subscribe().await?;
    let to_local = udp(v4(a.ip4, SRC_PORT), v4(b.ip4, DENIED), b"local");
    delivered(&a, &mut b, &to_local).await?;
    acl.engine.load(AclPolicy::default())?;
    delivered(&a, &mut b, &to_local).await?;
    let to_v6 = udp(
        SocketAddr::new(IpAddr::V6(a.ip6), SRC_PORT),
        SocketAddr::new(IpAddr::V6(b.ip6), DENIED),
        b"v6",
    );
    dropped(&a, &mut b, &mut events, &to_v6, reasons::DENIED).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.bypassed, stats.denied), (2, 1));

    // `accept_icmp_echo_reply`: an echo reply passes a deny-all policy, a request does not.
    let (a, mut b, acl) = key_pair(preset()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(AclPolicy::default())?;
    let reply = echo(a.ip4, b.ip4, ECHO_REPLY);
    delivered(&a, &mut b, &reply).await?;
    let request = echo(a.ip4, b.ip4, ECHO_REQUEST);
    dropped(&a, &mut b, &mut events, &request, reasons::PROTOCOL).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.bypassed, stats.protocol), (1, 1));

    // Both off: the same packets are judged by the policy.
    let config = AclFilterConfig {
        accept_to_local: None,
        accept_icmp_echo_reply: false,
        ..preset()
    };
    let (a, mut b, acl) = key_pair(config).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(AclPolicy::default())?;
    dropped(&a, &mut b, &mut events, &to_local, reasons::DENIED).await?;
    let reply = echo(a.ip4, b.ip4, ECHO_REPLY);
    dropped(&a, &mut b, &mut events, &reply, reasons::PROTOCOL).await?;
    let stats = acl.filter.stats();
    assert_eq!((stats.bypassed, stats.denied, stats.protocol), (0, 1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn ipv6_passes_unevaluated_in_the_preset_only() -> TestResult {
    let syn = 0x02;
    let (a, mut b, acl) = key_pair(preset()).await?;
    acl.engine.load(AclPolicy::default())?;
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

    // The default config judges the same packet by the policy.
    let (a, mut b, acl) = key_pair(AclFilterConfig::default()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(AclPolicy::default())?;
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
async fn replies_are_judged_by_the_policy_without_stateful_replies() -> TestResult {
    let (b_end, a_end) = (
        v4(Ipv4Addr::new(10, 0, 0, 2), 5000),
        v4(Ipv4Addr::new(10, 0, 0, 1), 6000),
    );
    let request = udp(b_end, a_end, b"request");
    let reply = udp(a_end, b_end, b"reply");

    // Control: the default config lets the reply through a deny-all policy.
    let (mut a, mut b, acl) = key_pair(AclFilterConfig::default()).await?;
    acl.engine.load(AclPolicy::default())?;
    delivered(&b, &mut a, &request).await?;
    delivered(&a, &mut b, &reply).await?;
    assert_eq!(acl.filter.stats().replies, 1);

    let (mut a, mut b, acl) = key_pair(preset()).await?;
    let mut events = b.subscribe().await?;
    acl.engine.load(AclPolicy::default())?;
    delivered(&b, &mut a, &request).await?;
    dropped(&a, &mut b, &mut events, &reply, reasons::DENIED).await?;
    // A policy accepting the reply's flow lets it in as a new flow.
    acl.engine.load(policy(vec![rule(
        &wg_peer_anchor(&a.public().to_bytes()),
        &b_end.to_string(),
    )]))?;
    delivered(&a, &mut b, &reply).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.replies, stats.accepted, stats.denied), (0, 1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn policy_updates_apply_to_the_next_packet_under_traffic() -> TestResult {
    let (a, mut b, acl) = by_source_pair(preset()).await?;
    let mut events = b.subscribe().await?;
    let sources = [gateway(1), gateway(2)];
    let to_b = v4(b.ip4, ALLOWED);
    let packet = |src: Ipv4Addr| udp(v4(src, SRC_PORT), to_b, b"traffic");

    // Each round lets one source in; both send before and after every reload, so a
    // cached verdict of the previous policy would show.
    for round in 0..6 {
        let open = sources[round % 2];
        acl.engine
            .load(udp_policy(&format!("{open}/32"), &b, ALLOWED))?;
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
