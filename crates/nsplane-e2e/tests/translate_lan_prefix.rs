//! LAN prefix mappings through the `Translator` between three engines over channel
//! transports: node `a` runs IPv4-only applications and translates, nodes `b` and `c` are
//! IPv6-only and each have a LAN behind them, both 192.168.1.0/24. `a` reaches `b`'s LAN as
//! 192.168.1.0/24 through `B_LAN6::/96` (the IPv4 address in the low 32 bits) and `c`'s as
//! the local range 10.9.1.0/24 through `C_LAN6::c0a8:100/120` (the remote network embedded
//! in the low bits). Covers both LANs answering at once, `ICMPv6` errors from the remapped
//! LAN, sources outside the embedded network, and a `Nat64Lan` gateway in front of the
//! remapped LAN. Every packet is checked by recomputing its checksums in full where it
//! arrives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, EngineBuilder, PacketBuf, Path,
    Peer, PeerId, TransportId,
};
use nsplane_e2e::{
    Node, Options, SharedFilter, TestResult, WAIT, icmp, payload, tcp, udp, verify_checksums,
};
use nsplane_nat::{
    LanPrefix, LanRoute, LanRoutes, Nat64Lan, Nat64LanConfig, Nat64LanSink, Nat64LanSource,
    SelfMapping, TranslationTable, Translator,
};
use nsplane_packet::checksum::internet_checksum;
use nsplane_packet::{Ipv4Header, Ipv6Header, protocol};
use tokio::time::timeout;

/// Node `a`'s own IPv4 address, translated to and from `SELF_EAM6`.
const SELF_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
const SELF_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);
/// The LAN behind `b` and behind `c`, the same IPv4 network on both.
const REMOTE_LAN4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 0);
/// `b`'s LAN: `a` uses its real range, under a /96.
const B_LAN4: Ipv4Addr = REMOTE_LAN4;
const B_LAN6: Ipv6Addr = Ipv6Addr::new(0xfd64, 0xb, 0, 0, 0, 0, 0, 0);
/// `c`'s LAN: `a` uses a local range of its own, under a /120 that embeds the real one.
const C_LAN4: Ipv4Addr = Ipv4Addr::new(10, 9, 1, 0);
const C_LAN6: Ipv6Addr = Ipv6Addr::new(0xfd64, 0xc, 0, 0, 0, 0, 0, 0);
/// The host addressed on both LANs, as `a` sees it behind `b` and behind `c`.
const B_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);
const C_HOST: Ipv4Addr = Ipv4Addr::new(10, 9, 1, 5);
const REMOTE_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);
/// A router on `c`'s LAN and how `a` sees it.
const REMOTE_ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 254);
const C_ROUTER: Ipv4Addr = Ipv4Addr::new(10, 9, 1, 254);
/// The gateway's SNAT address on `c`'s LAN.
const SNAT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

/// Key seeds of the nodes.
const A_SEED: u8 = 1;
const B_SEED: u8 = 2;
const C_SEED: u8 = 3;
/// Capacity of the links and the gateway's channels.
const CAPACITY: usize = 1024;
/// MTU of the gateway's local side.
const MTU: u16 = 1420;
/// `a`'s address on both links, and its transport ids for them.
const A_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000);
const A_TO_B: TransportId = TransportId::new(1);
const A_TO_C: TransportId = TransportId::new(3);
/// `b`'s and `c`'s transport ids and addresses.
const B_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);
const C_PATH: (TransportId, SocketAddr) = (
    TransportId::new(4),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 3000),
);

/// TCP flags.
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

type TestNode = Node<ChannelTransport>;

/// `c`'s LAN prefix on `a`: `C_LAN4/24` to `C_LAN6` plus the embedded `REMOTE_LAN4/24`.
fn c_lan(c: PeerId) -> LanPrefix {
    LanPrefix {
        lan4: (C_LAN4, 24),
        lan6: (lan6(C_LAN6, REMOTE_LAN4), 120),
        peer: Some(c),
    }
}

/// `a`'s table: its self mapping, `b`'s LAN under a /96 and `c`'s remapped one.
fn table(b: PeerId, c: PeerId) -> TestResult<TranslationTable> {
    Ok(TranslationTable::builder()
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: SELF_EAM6,
        })
        .lan(LanPrefix {
            lan4: (B_LAN4, 24),
            lan6: (B_LAN6, 96),
            peer: Some(b),
        })
        .lan(c_lan(c))
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

/// The address of `host` inside the /96 LAN prefix `prefix`.
fn lan6(prefix: Ipv6Addr, host: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(prefix) | u128::from(u32::from(host)))
}

/// `a` with one transport per link and the translator as its filter.
fn translating_node(
    translator: &Arc<Translator>,
    links: impl IntoIterator<Item = ChannelTransport>,
) -> TestResult<TestNode> {
    Node::with_builder(A_SEED, A_TO_B, A_ADDR, Options::default(), |builder| {
        links.into_iter().fold(
            builder.filter(Box::new(SharedFilter(Arc::clone(translator)))),
            EngineBuilder::transport,
        )
    })
}

/// Three peers: `a` translating with the table above, `b` and `c` IPv6-only.
///
/// `a` routes `b`'s LAN (both prefixes) to `b` and `c`'s to `c`; `b` and `c` route and
/// accept `a`'s `eam6`.
async fn trio() -> TestResult<(TestNode, TestNode, TestNode, Arc<Translator>)> {
    // Placeholder peers until `b` and `c` have ids on `a`.
    let translator = Arc::new(Translator::new(table(
        PeerId::new(u32::MAX),
        PeerId::new(u32::MAX - 1),
    )?));
    let (a_b, b_a) = ChannelTransport::pair(CAPACITY, (A_TO_B, A_ADDR), B_PATH);
    let (a_c, c_a) = ChannelTransport::pair(CAPACITY, (A_TO_C, A_ADDR), C_PATH);
    let a = translating_node(&translator, [a_b, a_c])?;
    let b = Node::new(B_SEED, B_PATH.0, B_PATH.1, b_a, Options::default());
    let c = Node::new(C_SEED, C_PATH.0, C_PATH.1, c_a, Options::default());

    for (node, via, lan4, lan6) in [(&b, A_TO_B, B_LAN4, B_LAN6), (&c, A_TO_C, C_LAN4, C_LAN6)] {
        let mut peer = node.as_peer(via);
        peer.allowed_ips = vec![allowed(lan4, 24), allowed(lan6, 96)];
        a.handle.add_or_update_peer(peer).await?;
        let mut peer = a.as_peer(node.path.transport);
        peer.allowed_ips = vec![allowed(SELF_EAM6, 128)];
        node.handle.add_or_update_peer(peer).await?;
    }
    translator.store(table(a.peer_of(&b).await?, a.peer_of(&c).await?)?);
    Ok((a, b, c, translator))
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

/// The next packet `node` delivers, checked to be IPv4 to `dst` with protocol `proto`, a
/// TTL of 63 and valid checksums; returns its source and transport segment.
async fn next_v4(node: &mut TestNode, dst: Ipv4Addr, proto: u8) -> TestResult<(Ipv4Addr, Vec<u8>)> {
    let (_, packet) = node.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv4Header::parse(&packet)?;
    assert_eq!(ip.dst(), dst);
    assert_eq!((ip.protocol(), ip.ttl()), (proto, 63));
    Ok((ip.src(), segment.to_vec()))
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

/// Payload of a datagram of the concurrent test: which LAN it is for and a sequence number,
/// padded to `len` bytes.
fn tagged(lan: u8, seq: u8, len: usize) -> Vec<u8> {
    let mut data = vec![lan, seq];
    data.extend(payload(len));
    data
}

/// How many datagrams each LAN gets and sends in the concurrent test.
const ROUNDS: u8 = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_with_the_same_remote_lan_answer_at_once() -> TestResult {
    let (mut a, mut b, mut c, translator) = trio().await?;
    let b_host6 = lan6(B_LAN6, REMOTE_HOST);
    let c_host6 = lan6(C_LAN6, REMOTE_HOST);
    let lans = [(B_HOST, b_host6), (C_HOST, c_host6)];

    // `a`'s app sends to both LANs, interleaved.
    let mut sent = [Vec::new(), Vec::new()];
    for seq in 0..ROUNDS {
        for (lan, (host4, _)) in (0_u8..).zip(lans) {
            let request = udp(
                v4(SELF_EAM4, 40001),
                v4(host4, 5001),
                &tagged(lan, seq, 200),
            );
            a.send_with_room(&request).await?;
            sent[usize::from(lan)].push(request);
        }
    }
    // Each LAN host sees the remote address 192.168.1.5 under its own prefix, in order.
    for (node, host6, sent) in [(&mut b, b_host6, &sent[0]), (&mut c, c_host6, &sent[1])] {
        for request in sent {
            let got = expect_v6(node, (SELF_EAM6, host6), protocol::UDP).await?;
            assert_same_segment(&got, request, 6);
        }
    }

    // Both answer at once.
    let answer = |node: &TestNode, lan: u8, host6: Ipv6Addr| {
        let replies: Vec<_> = (0..ROUNDS)
            .map(|seq| {
                udp(
                    v6(host6, 5001),
                    v6(SELF_EAM6, 40001),
                    &tagged(lan, seq, 600),
                )
            })
            .collect();
        let local = node.local.clone();
        async move {
            for reply in &replies {
                local.send(PacketBuf::from_packet(reply)).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(replies)
        }
    };
    let (b_replies, c_replies) = tokio::try_join!(
        tokio::spawn(answer(&b, 0, b_host6)),
        tokio::spawn(answer(&c, 1, c_host6)),
    )?;
    let replies = [b_replies?, c_replies?];

    // `a`'s app gets each reply from the address it used for that LAN; per LAN in order.
    let mut next = [0_usize; 2];
    for _ in 0..2 * usize::from(ROUNDS) {
        let (src, got) = next_v4(&mut a, SELF_EAM4, protocol::UDP).await?;
        let lan = usize::from(got[8]);
        assert_eq!(src, lans[lan].0, "reply for LAN {lan}");
        assert_same_segment(&got, &replies[lan][next[lan]], 6);
        assert_eq!(usize::from(got[9]), next[lan]);
        next[lan] += 1;
    }

    // A TCP handshake to each LAN.
    for ((host4, host6), node) in lans.into_iter().zip([&mut b, &mut c]) {
        let syn = tcp(v4(SELF_EAM4, 40002), v4(host4, 80), SYN, (100, 0), &[]);
        a.send_with_room(&syn).await?;
        let got = expect_v6(node, (SELF_EAM6, host6), protocol::TCP).await?;
        assert_same_segment(&got, &syn, 16);
        let syn_ack = tcp(
            v6(host6, 80),
            v6(SELF_EAM6, 40002),
            SYN | ACK,
            (200, 101),
            &[],
        );
        node.send(&syn_ack).await?;
        let (src, got) = next_v4(&mut a, SELF_EAM4, protocol::TCP).await?;
        assert_eq!(src, host4);
        assert_same_segment(&got, &syn_ack, 16);
    }

    let stats = translator.stats();
    let packets = 2 * u64::from(ROUNDS) + 2;
    assert_eq!(
        (stats.translated_out, stats.translated_in),
        (packets, packets)
    );
    assert_eq!((stats.dropped_out, stats.dropped_in), (0, 0));
    Ok(())
}

/// The type, code and second header word of an ICMP or `ICMPv6` error.
type IcmpError = (u8, u8, [u8; 4]);

#[tokio::test]
async fn icmp_errors_from_the_remapped_lan_quote_the_local_range() -> TestResult {
    let (mut a, _b, mut c, _translator) = trio().await?;
    let router6 = lan6(C_LAN6, REMOTE_ROUTER);
    // (ICMPv6 type, code, second word) -> (ICMP type, code, second word).
    let cases: [(IcmpError, IcmpError); 2] = [
        // Destination unreachable, port unreachable.
        ((1, 4, [0; 4]), (3, 3, [0; 4])),
        // Packet Too Big at 1300 bytes: fragmentation needed at 1280 (20 bytes less).
        ((2, 0, 1300_u32.to_be_bytes()), (3, 4, [0, 0, 0x05, 0x00])),
    ];
    for (i, ((kind6, code6, rest6), (kind4, code4, rest4))) in cases.into_iter().enumerate() {
        let port = 40010 + u16::try_from(i)?;
        let original = udp(v4(SELF_EAM4, port), v4(C_HOST, 5010), &payload(100));
        a.send_with_room(&original).await?;
        let (_, translated) = c.expect_delivery().await?;

        // A router on `c`'s LAN reports an error about the packet, quoting it in full.
        let error = icmp(
            router6.into(),
            SELF_EAM6.into(),
            (kind6, code6),
            rest6,
            &translated,
        );
        c.send(&error).await?;
        let (src, got) = next_v4(&mut a, SELF_EAM4, protocol::ICMP).await?;
        assert_eq!(src, C_ROUTER);
        assert_eq!((got[0], got[1]), (kind4, code4));
        assert_eq!(got[4..8], rest4);

        // The quoted packet is the original IPv4 packet again: the local range `a`'s app
        // used, the transport segment unchanged, all checksums valid.
        let quoted = &got[8..];
        verify_checksums(quoted)?;
        let (ip, segment) = Ipv4Header::parse(quoted)?;
        assert_eq!((ip.src(), ip.dst()), (SELF_EAM4, C_HOST));
        assert_eq!(ip.protocol(), protocol::UDP);
        assert_eq!(internet_checksum(&quoted[..20]), 0);
        assert_eq!(segment, &original[20..]);
    }
    Ok(())
}

#[tokio::test]
async fn sources_outside_the_embedded_network_are_not_delivered() -> TestResult {
    let (mut a, _b, c, translator) = trio().await?;
    // Inside `c`'s /96 base but in 192.168.2.0/24, not the embedded 192.168.1.0/24: it
    // would read as 10.9.2.5 if only the host bits were mapped.
    let outside = lan6(C_LAN6, Ipv4Addr::new(192, 168, 2, 5));
    c.send(&udp(v6(outside, 5020), v6(SELF_EAM6, 40020), &payload(64)))
        .await?;
    a.expect_no_delivery().await?;
    let stats = translator.stats();
    assert_eq!((stats.translated_in, stats.dropped_in), (0, 1));

    // The embedded network still gets through.
    let inside = lan6(C_LAN6, REMOTE_HOST);
    let request = udp(v6(inside, 5020), v6(SELF_EAM6, 40020), &payload(64));
    c.send(&request).await?;
    let (src, got) = next_v4(&mut a, SELF_EAM4, protocol::UDP).await?;
    assert_eq!(src, C_HOST);
    assert_same_segment(&got, &request, 6);
    Ok(())
}

#[tokio::test]
async fn a_gateway_resolves_the_embedded_address_on_its_lan() -> TestResult {
    // `a` translates with `c`'s remapped LAN only; `c` is a `Nat64Lan` gateway that routes
    // `C_LAN6::/96` to 192.168.1.0/24 and knows nothing of `a`'s local range.
    let translator = Arc::new(Translator::new(
        TranslationTable::builder()
            .self_mapping(SelfMapping {
                eam4: SELF_EAM4,
                eam6: SELF_EAM6,
            })
            .lan(c_lan(PeerId::new(u32::MAX)))
            .build()?,
    ));
    let (a_c, c_a) = ChannelTransport::pair(CAPACITY, (A_TO_C, A_ADDR), C_PATH);
    let mut a = translating_node(&translator, [a_c])?;
    let route = LanRoute::new((C_LAN6, 96), (REMOTE_LAN4, 24), SNAT)?;
    let nat = Arc::new(Nat64Lan::new(
        LanRoutes::new(vec![route]),
        Nat64LanConfig::default(),
    ));
    let (source, lan_out, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let (sink, mut lan_in) = ChannelSink::new(CAPACITY);
    let gateway = EngineBuilder::new(
        Nat64LanSource::new(source, Arc::clone(&nat)),
        Nat64LanSink::new(sink, Arc::clone(&nat)),
    )
    .private_key(StaticSecret::from([C_SEED; 32]))
    .transport(c_a)
    .build()?;
    let mut peer = a.as_peer(C_PATH.0);
    peer.allowed_ips = vec![allowed(SELF_EAM6, 128)];
    gateway.handle().add_or_update_peer(peer).await?;
    let c_key = PublicKey::from(&StaticSecret::from([C_SEED; 32]));
    a.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![allowed(C_LAN4, 24), allowed(C_LAN6, 96)],
            path: Some(Path {
                transport: A_TO_C,
                addr: C_PATH.1,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(c_key)
        })
        .await?;
    let c = a.handle.peer_id(c_key).await?.ok_or("unknown peer")?;
    translator.store(
        TranslationTable::builder()
            .self_mapping(SelfMapping {
                eam4: SELF_EAM4,
                eam6: SELF_EAM6,
            })
            .lan(c_lan(c))
            .build()?,
    );

    // `a`'s app sends to 10.9.1.5; the LAN host 192.168.1.5 gets it from the SNAT address.
    let request = udp(v4(SELF_EAM4, 40030), v4(C_HOST, 5030), &payload(300));
    a.send_with_room(&request).await?;
    let (_, packet) = timeout(WAIT, lan_in.recv())
        .await?
        .ok_or("gateway sink closed")?;
    let packet = packet.as_packet().to_vec();
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv4Header::parse(&packet)?;
    assert_eq!(
        (ip.src(), ip.dst(), ip.protocol()),
        (SNAT, REMOTE_HOST, protocol::UDP)
    );
    assert_eq!(segment[2..4], 5030_u16.to_be_bytes());
    assert_eq!(segment[8..], request[28..]);
    let snat_port = u16::from_be_bytes([segment[0], segment[1]]);

    // The host answers; `a`'s app gets the reply from 10.9.1.5.
    let reply = udp(v4(REMOTE_HOST, 5030), v4(SNAT, snat_port), &payload(500));
    lan_out.send(PacketBuf::from_packet(&reply)).await?;
    let (src, got) = next_v4(&mut a, SELF_EAM4, protocol::UDP).await?;
    assert_eq!(src, C_HOST);
    assert_eq!(
        got[..4],
        [5030_u16.to_be_bytes(), 40030_u16.to_be_bytes()].concat()
    );
    assert_eq!(got[8..], reply[28..]);

    let stats = nat.stats();
    assert_eq!((stats.forwarded, stats.reversed), (1, 1));
    drop(gateway);
    Ok(())
}
