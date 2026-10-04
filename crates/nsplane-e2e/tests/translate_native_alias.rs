//! A native IPv4 alias through the `Translator` between two engines over a channel
//! transport: node `a` runs IPv4-only applications and translates, node `b` is IPv6-only
//! and runs no filter. `a` reaches `b`'s native IPv6 address `node6` at a local IPv4
//! address (quick-v2 `alias6(b)`, `TranslationTableBuilder::peer_with_native_alias4`):
//! `b` sees `a`'s `node4` talking to its `node6`, and `a` sees `b`'s replies come from the
//! native alias. Covers UDP, TCP and ICMP echo, next to the peer's `alias4` and `alias6`.
//! Every packet is checked by recomputing its checksums in full where it arrives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::{AllowedIp, ChannelTransport};
use nsplane_e2e::{
    Node, Options, SharedFilter, TestResult, channel_pair_with, icmp, introduce, payload, tcp, udp,
    verify_checksums,
};
use nsplane_nat::{PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_packet::{Ipv4Header, Ipv6Header, PeerId, protocol};

/// Node `a`'s own IPv4 address, translated to and from `SELF_NODE4`.
const SELF4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
const SELF_NODE4: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);
/// Node `b`'s /127 group and node `a`'s aliases for it.
const PEER_NODE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 0);
const PEER_NODE4: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 1);
const PEER_ALIAS4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const PEER_ALIAS6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaa, 0, 0, 0, 0, 0, 2);
/// The native IPv4 alias: a local IPv4 address for `b`'s `node6`.
const PEER_NATIVE4: Ipv4Addr = Ipv4Addr::new(100, 64, 1, 2);

/// TCP flags.
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;

type TestNode = Node<ChannelTransport>;

/// `a`'s table with `b` as `peer`.
fn table(peer: PeerId) -> TestResult<TranslationTable> {
    Ok(TranslationTable::builder()
        .self_mapping(SelfMapping {
            self4: SELF4,
            node4: SELF_NODE4,
        })
        .peer_with_native_alias4(
            peer,
            PeerMapping {
                node6: PEER_NODE6,
                node4: PEER_NODE4,
                alias6: Some(PEER_ALIAS6),
                alias4: Some(PEER_ALIAS4),
            },
            PEER_NATIVE4,
        )
        .build()?)
}

fn allowed(addr: impl Into<IpAddr>, cidr: u8) -> AllowedIp {
    AllowedIp {
        addr: addr.into(),
        cidr,
    }
}

const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

const fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ip), port)
}

/// Two peers, `a` translating with the table above and `b` IPv6-only.
///
/// `a` routes `b`'s aliases (`alias4`, the native alias, `alias6`) to `b` and accepts
/// `b`'s `node4` and `node6`; `b` routes and accepts `a`'s `node4`.
async fn pair() -> TestResult<(TestNode, TestNode, Arc<Translator>)> {
    // A placeholder peer until `b` has an id on `a`.
    let translator = Arc::new(Translator::new(table(PeerId::new(u32::MAX))?));
    let filter = Arc::clone(&translator);
    let (a, b) = channel_pair_with(Options::default(), |seed, builder| match seed {
        1 => builder.filter(Box::new(SharedFilter(Arc::clone(&filter)))),
        _ => builder,
    })?;
    introduce(&a, &b, None).await?;
    let mut peer = b.as_peer(a.path.transport);
    peer.allowed_ips = vec![
        allowed(PEER_ALIAS4, 32),
        allowed(PEER_NATIVE4, 32),
        allowed(PEER_ALIAS6, 128),
        allowed(PEER_NODE4, 128),
        allowed(PEER_NODE6, 128),
    ];
    a.handle.add_or_update_peer(peer).await?;
    let mut peer = a.as_peer(b.path.transport);
    peer.allowed_ips = vec![allowed(SELF_NODE4, 128)];
    b.handle.add_or_update_peer(peer).await?;
    translator.store(table(a.peer_of(&b).await?)?);
    Ok((a, b, translator))
}

/// The next packet `node` delivers, checked to be IPv6 from `src` to `dst` with protocol
/// `proto`, a hop limit of 63 and valid checksums; returns its transport segment.
async fn expect_v6(
    node: &mut TestNode,
    (src, dst): (Ipv6Addr, Ipv6Addr),
    proto: u8,
) -> TestResult<Vec<u8>> {
    let (_, packet) = node.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv6Header::parse(&packet)?;
    assert_eq!((ip.src(), ip.dst()), (src, dst));
    assert_eq!((ip.next_header(), ip.hop_limit()), (proto, 63));
    Ok(segment.to_vec())
}

/// The next packet `node` delivers, checked to be IPv4 from `src` to `dst` with protocol
/// `proto`, a TTL of 63 and valid checksums; returns its transport segment.
async fn expect_v4(
    node: &mut TestNode,
    (src, dst): (Ipv4Addr, Ipv4Addr),
    proto: u8,
) -> TestResult<Vec<u8>> {
    let (_, packet) = node.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv4Header::parse(&packet)?;
    assert_eq!((ip.src(), ip.dst()), (src, dst));
    assert_eq!((ip.protocol(), ip.ttl()), (proto, 63));
    Ok(segment.to_vec())
}

/// The transport segment of `packet`.
fn segment(packet: &[u8]) -> &[u8] {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => &packet[20..],
        _ => &packet[40..],
    }
}

/// Checks that the translated segment `got` equals the segment of `sent` except for the
/// checksum at `checksum` (moved to the new pseudo-header).
fn assert_same_segment(got: &[u8], sent: &[u8], checksum: usize) {
    let sent = segment(sent);
    assert_eq!(got.len(), sent.len());
    assert_eq!(got[..checksum], sent[..checksum]);
    assert_eq!(got[checksum + 2..], sent[checksum + 2..]);
}

#[tokio::test]
async fn ipv4_app_reaches_native_ipv6_over_udp() -> TestResult {
    let (mut a, mut b, translator) = pair().await?;
    let request = udp(v4(SELF4, 41001), v4(PEER_NATIVE4, 6001), &payload(300));
    a.send_with_room(&request).await?;
    let got = expect_v6(&mut b, (SELF_NODE4, PEER_NODE6), protocol::UDP).await?;
    assert_same_segment(&got, &request, 6);

    let reply = udp(v6(PEER_NODE6, 6001), v6(SELF_NODE4, 41001), &payload(700));
    b.send(&reply).await?;
    let got = expect_v4(&mut a, (PEER_NATIVE4, SELF4), protocol::UDP).await?;
    assert_same_segment(&got, &reply, 6);

    let stats = translator.stats();
    assert_eq!((stats.translated_out, stats.translated_in), (1, 1));
    assert_eq!((stats.dropped_out, stats.dropped_in), (0, 0));
    Ok(())
}

#[tokio::test]
async fn ipv4_app_reaches_native_ipv6_over_tcp() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    let (client, server) = (v4(SELF4, 41002), v4(PEER_NATIVE4, 6002));
    let (client6, server6) = (v6(SELF_NODE4, 41002), v6(PEER_NODE6, 6002));
    let request = payload(500);
    let response = payload(900);

    // Handshake, request and response, each segment checked where it arrives.
    let outbound = [
        tcp(client, server, SYN, (100, 0), &[]),
        tcp(client, server, ACK, (101, 201), &[]),
        tcp(client, server, PSH_ACK, (101, 201), &request),
    ];
    let inbound = [
        tcp(server6, client6, SYN | ACK, (200, 101), &[]),
        tcp(server6, client6, PSH_ACK, (201, 601), &response),
    ];
    for (i, sent) in outbound.iter().enumerate() {
        a.send_with_room(sent).await?;
        let got = expect_v6(&mut b, (SELF_NODE4, PEER_NODE6), protocol::TCP).await?;
        assert_same_segment(&got, sent, 16);
        if let Some(reply) = inbound.get(i) {
            b.send(reply).await?;
            let got = expect_v4(&mut a, (PEER_NATIVE4, SELF4), protocol::TCP).await?;
            assert_same_segment(&got, reply, 16);
        }
    }
    Ok(())
}

#[tokio::test]
async fn icmp_echo_to_the_native_alias_is_translated_both_ways() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    let rest = [0x12, 0x34, 0, 1];
    let data = payload(56);

    let request = icmp(SELF4.into(), PEER_NATIVE4.into(), (8, 0), rest, &data);
    a.send_with_room(&request).await?;
    let got = expect_v6(&mut b, (SELF_NODE4, PEER_NODE6), protocol::ICMPV6).await?;
    assert_eq!(got[..2], [128, 0]);
    assert_eq!(got[4..8], rest);
    assert_eq!(got[8..], data);

    let reply = icmp(PEER_NODE6.into(), SELF_NODE4.into(), (129, 0), rest, &data);
    b.send(&reply).await?;
    let got = expect_v4(&mut a, (PEER_NATIVE4, SELF4), protocol::ICMP).await?;
    assert_eq!(got[..2], [0, 0]);
    assert_eq!(got[4..8], rest);
    assert_eq!(got[8..], data);
    Ok(())
}

#[tokio::test]
async fn the_native_alias_coexists_with_alias4() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    // The same application port to both IPv4 aliases of `b`: `alias4` reaches `node4`,
    // the native alias reaches `node6`, and each reply comes back from its own alias.
    for (alias, node) in [(PEER_ALIAS4, PEER_NODE4), (PEER_NATIVE4, PEER_NODE6)] {
        let request = udp(v4(SELF4, 41003), v4(alias, 6003), &payload(64));
        a.send_with_room(&request).await?;
        let got = expect_v6(&mut b, (SELF_NODE4, node), protocol::UDP).await?;
        assert_same_segment(&got, &request, 6);
        let reply = udp(v6(node, 6003), v6(SELF_NODE4, 41003), &payload(64));
        b.send(&reply).await?;
        let got = expect_v4(&mut a, (alias, SELF4), protocol::UDP).await?;
        assert_same_segment(&got, &reply, 6);
    }
    Ok(())
}
