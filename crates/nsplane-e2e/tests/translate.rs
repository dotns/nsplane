//! The `Translator` between two engines over a channel transport: node `a` runs IPv4-only
//! applications and translates, node `b` is IPv6-only and runs no filter. Covers the
//! peer `eam4 <-> eam6`, self `eam4 <-> eam6`, `local6 <-> peer6` and `lan4 <-> lan6` mappings
//! for UDP, TCP and ICMP echo, `ICMPv6` errors about translated packets, and a table
//! replacement while traffic flows. Every packet is checked by recomputing its checksums in
//! full where it arrives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nsplane::{AllowedIp, ChannelTransport};
use nsplane_e2e::{
    Node, Options, QUIET, SharedFilter, TestResult, WAIT, channel_pair_with, icmp, introduce,
    payload, tcp, udp, verify_checksums,
};
use nsplane_nat::{LanPrefix, PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_packet::checksum::internet_checksum;
use nsplane_packet::{Ipv4Header, Ipv6Header, PeerId, protocol};
use tokio::time::timeout;

/// Node `a`'s own IPv4 address, translated to and from `SELF_EAM6`.
const SELF_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
const SELF_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);
/// Node `b`'s `peer6`, `eam6` and node `a`'s local addresses for it.
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 0);
const PEER_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 1);
const PEER_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const PEER_LOCAL6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaa, 0, 0, 0, 0, 0, 2);
/// The `eam4` the table replacement test switches to.
const NEW_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
/// The LAN behind `a` and the LAN behind `b`, in IPv4 (as `a` sees them) and IPv6.
const A_LAN4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 0);
const A_LAN6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xa, 0, 0, 0, 0, 0, 0);
const B_LAN4: Ipv4Addr = Ipv4Addr::new(192, 168, 2, 0);
const B_LAN6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xb, 0, 0, 0, 0, 0, 0);

/// TCP flags.
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;

type TestNode = Node<ChannelTransport>;

/// `a`'s table with `b` as `peer`, its IPv4 EAM address `eam4`.
fn table(peer: PeerId, eam4: Ipv4Addr) -> TestResult<TranslationTable> {
    Ok(TranslationTable::builder()
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: SELF_EAM6,
        })
        .peer(
            peer,
            PeerMapping {
                peer6: PEER6,
                eam6: PEER_EAM6,
                local6: Some(PEER_LOCAL6),
                eam4: Some(eam4),
            },
        )
        .lan(LanPrefix {
            lan4: (A_LAN4, 24),
            lan6: (A_LAN6, 96),
            peer: None,
        })
        .lan(LanPrefix {
            lan4: (B_LAN4, 24),
            lan6: (B_LAN6, 96),
            peer: Some(peer),
        })
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

/// Two peers, `a` translating with the table above and `b` IPv6-only.
///
/// `a` routes `b`'s local addresses (both `eam4`s of the tests, `local6`) and LAN to `b` and
/// accepts `b`'s `eam6`, `peer6` and `lan6`; `b` routes and accepts `a`'s `eam6`,
/// native IPv6 address and `lan6`.
async fn pair() -> TestResult<(TestNode, TestNode, Arc<Translator>)> {
    // A placeholder peer until `b` has an id on `a`.
    let translator = Arc::new(Translator::new(table(PeerId::new(u32::MAX), PEER_EAM4)?));
    let filter = Arc::clone(&translator);
    let (a, b) = channel_pair_with(Options::default(), |seed, builder| match seed {
        1 => builder.filter(Box::new(SharedFilter(Arc::clone(&filter)))),
        _ => builder,
    })?;
    introduce(&a, &b, None).await?;
    let mut peer = b.as_peer(a.path.transport);
    peer.allowed_ips = vec![
        allowed(PEER_EAM4, 32),
        allowed(NEW_EAM4, 32),
        allowed(B_LAN4, 24),
        allowed(PEER_LOCAL6, 128),
        allowed(PEER_EAM6, 128),
        allowed(PEER6, 128),
        allowed(B_LAN6, 96),
    ];
    a.handle.add_or_update_peer(peer).await?;
    let mut peer = a.as_peer(b.path.transport);
    peer.allowed_ips = vec![
        allowed(SELF_EAM6, 128),
        allowed(a.ip6, 128),
        allowed(A_LAN6, 96),
    ];
    b.handle.add_or_update_peer(peer).await?;
    translator.store(table(a.peer_of(&b).await?, PEER_EAM4)?);
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

/// A UDP datagram `a` sends from `client` (IPv4) arrives at `b` as IPv6 from `client6` to
/// `server6`, and `b`'s reply arrives at `a` as IPv4 to `client` from `server`.
async fn udp_round_trip(
    (a, b): (&mut TestNode, &mut TestNode),
    (client, server): (SocketAddr, SocketAddr),
    (client6, server6): (SocketAddr, SocketAddr),
) -> TestResult {
    let (IpAddr::V4(c4), IpAddr::V4(s4)) = (client.ip(), server.ip()) else {
        return Err("IPv4 client and server".into());
    };
    let (IpAddr::V6(c6), IpAddr::V6(s6)) = (client6.ip(), server6.ip()) else {
        return Err("IPv6 client and server".into());
    };
    let request = udp(client, server, &payload(300));
    a.send_with_room(&request).await?;
    let got = expect_v6(b, (c6, s6), protocol::UDP).await?;
    assert_same_segment(&got, &request, 6);

    let reply = udp(server6, client6, &payload(700));
    b.send(&reply).await?;
    let got = expect_v4(a, (s4, c4), protocol::UDP).await?;
    assert_same_segment(&got, &reply, 6);
    Ok(())
}

#[tokio::test]
async fn ipv4_app_reaches_ipv6_only_peer_over_udp() -> TestResult {
    let (mut a, mut b, translator) = pair().await?;
    udp_round_trip(
        (&mut a, &mut b),
        (v4(SELF_EAM4, 40001), v4(PEER_EAM4, 5001)),
        (v6(SELF_EAM6, 40001), v6(PEER_EAM6, 5001)),
    )
    .await?;
    // The other direction of the mapping: `b` opens the flow.
    let request = udp(v6(PEER_EAM6, 5002), v6(SELF_EAM6, 40002), &payload(64));
    b.send(&request).await?;
    let got = expect_v4(&mut a, (PEER_EAM4, SELF_EAM4), protocol::UDP).await?;
    assert_same_segment(&got, &request, 6);
    let reply = udp(v4(SELF_EAM4, 40002), v4(PEER_EAM4, 5002), &payload(64));
    a.send_with_room(&reply).await?;
    let got = expect_v6(&mut b, (SELF_EAM6, PEER_EAM6), protocol::UDP).await?;
    assert_same_segment(&got, &reply, 6);

    let stats = translator.stats();
    assert_eq!((stats.translated_out, stats.translated_in), (2, 2));
    assert_eq!((stats.dropped_out, stats.dropped_in), (0, 0));
    Ok(())
}

#[tokio::test]
async fn ipv4_app_reaches_ipv6_only_peer_over_tcp() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    let (client, server) = (v4(SELF_EAM4, 40003), v4(PEER_EAM4, 5003));
    let (client6, server6) = (v6(SELF_EAM6, 40003), v6(PEER_EAM6, 5003));
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
        let got = expect_v6(&mut b, (SELF_EAM6, PEER_EAM6), protocol::TCP).await?;
        assert_same_segment(&got, sent, 16);
        if let Some(reply) = inbound.get(i) {
            b.send(reply).await?;
            let got = expect_v4(&mut a, (PEER_EAM4, SELF_EAM4), protocol::TCP).await?;
            assert_same_segment(&got, reply, 16);
        }
    }
    Ok(())
}

#[tokio::test]
async fn local6_and_peer6_are_rewritten_both_ways() -> TestResult {
    let (mut a, mut b, translator) = pair().await?;
    let (client, local6, peer6) = (v6(a.ip6, 40004), v6(PEER_LOCAL6, 5004), v6(PEER6, 5004));

    let request = udp(client, local6, &payload(256));
    a.send(&request).await?;
    let (_, packet) = b.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv6Header::parse(&packet)?;
    assert_eq!((ip.src(), ip.dst()), (a.ip6, PEER6));
    assert_same_segment(segment, &request, 6);

    let reply = udp(peer6, client, &payload(512));
    b.send(&reply).await?;
    let (_, packet) = a.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv6Header::parse(&packet)?;
    assert_eq!((ip.src(), ip.dst()), (PEER_LOCAL6, a.ip6));
    assert_same_segment(segment, &reply, 6);

    let stats = translator.stats();
    assert_eq!((stats.rewritten_out, stats.rewritten_in), (1, 1));
    Ok(())
}

#[tokio::test]
async fn lan4_reaches_lan6_and_back() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    let a_host = Ipv4Addr::new(192, 168, 1, 10);
    let b_host = Ipv4Addr::new(192, 168, 2, 20);

    // A LAN host behind `a` reaches a LAN host behind `b`, which answers natively.
    udp_round_trip(
        (&mut a, &mut b),
        (v4(a_host, 40005), v4(b_host, 5005)),
        (
            v6(lan6(A_LAN6, a_host), 40005),
            v6(lan6(B_LAN6, b_host), 5005),
        ),
    )
    .await?;

    // `b` reaches the LAN host behind `a` from its eam6 through `a`'s lan6 prefix.
    let request = udp(
        v6(PEER_EAM6, 5006),
        v6(lan6(A_LAN6, a_host), 40006),
        &payload(128),
    );
    b.send(&request).await?;
    let got = expect_v4(&mut a, (PEER_EAM4, a_host), protocol::UDP).await?;
    assert_same_segment(&got, &request, 6);
    let reply = udp(v4(a_host, 40006), v4(PEER_EAM4, 5006), &payload(128));
    a.send_with_room(&reply).await?;
    let got = expect_v6(&mut b, (lan6(A_LAN6, a_host), PEER_EAM6), protocol::UDP).await?;
    assert_same_segment(&got, &reply, 6);
    Ok(())
}

#[tokio::test]
async fn icmp_echo_is_translated_both_ways() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    let rest = [0x12, 0x34, 0, 1];
    let data = payload(56);

    let request = icmp(SELF_EAM4.into(), PEER_EAM4.into(), (8, 0), rest, &data);
    a.send_with_room(&request).await?;
    let got = expect_v6(&mut b, (SELF_EAM6, PEER_EAM6), protocol::ICMPV6).await?;
    assert_eq!(got[..2], [128, 0]);
    assert_eq!(got[4..8], rest);
    assert_eq!(got[8..], data);

    let reply = icmp(PEER_EAM6.into(), SELF_EAM6.into(), (129, 0), rest, &data);
    b.send(&reply).await?;
    let got = expect_v4(&mut a, (PEER_EAM4, SELF_EAM4), protocol::ICMP).await?;
    assert_eq!(got[..2], [0, 0]);
    assert_eq!(got[4..8], rest);
    assert_eq!(got[8..], data);
    Ok(())
}

/// The type, code and second header word of an ICMP or `ICMPv6` error.
type IcmpError = (u8, u8, [u8; 4]);

#[tokio::test]
async fn icmpv6_errors_about_translated_packets_arrive_as_icmp() -> TestResult {
    let (mut a, mut b, _translator) = pair().await?;
    // (ICMPv6 type, code, second word) -> (ICMP type, code, second word).
    let cases: [(IcmpError, IcmpError); 3] = [
        // Destination unreachable, port unreachable.
        ((1, 4, [0; 4]), (3, 3, [0; 4])),
        // Time exceeded in transit.
        ((3, 0, [0; 4]), (11, 0, [0; 4])),
        // Packet Too Big at 1300 bytes: fragmentation needed at 1280 (20 bytes less).
        ((2, 0, 1300_u32.to_be_bytes()), (3, 4, [0, 0, 0x05, 0x00])),
    ];
    for (i, ((kind6, code6, rest6), (kind4, code4, rest4))) in cases.into_iter().enumerate() {
        let port = 40010 + u16::try_from(i)?;
        let original = udp(v4(SELF_EAM4, port), v4(PEER_EAM4, 5010), &payload(100));
        a.send_with_room(&original).await?;
        let (_, translated) = b.expect_delivery().await?;

        // `b` reports an error about the packet it received, quoting it in full.
        let error = icmp(
            PEER_EAM6.into(),
            SELF_EAM6.into(),
            (kind6, code6),
            rest6,
            &translated,
        );
        b.send(&error).await?;
        let got = expect_v4(&mut a, (PEER_EAM4, SELF_EAM4), protocol::ICMP).await?;
        assert_eq!((got[0], got[1]), (kind4, code4));
        assert_eq!(got[4..8], rest4);

        // The quoted packet is the original IPv4 packet again: the addresses `a`'s app
        // used, the transport segment unchanged, all checksums valid.
        let quoted = &got[8..];
        verify_checksums(quoted)?;
        let (ip, segment) = Ipv4Header::parse(quoted)?;
        assert_eq!((ip.src(), ip.dst()), (SELF_EAM4, PEER_EAM4));
        assert_eq!(ip.protocol(), protocol::UDP);
        assert_eq!(internet_checksum(&quoted[..20]), 0);
        assert_eq!(segment, &original[20..]);
    }
    Ok(())
}

/// Payload of a packet the table replacement test sends: which `eam4` it went to and a
/// sequence number.
fn tagged(new: bool, seq: u32) -> Vec<u8> {
    let mut data = vec![u8::from(new)];
    data.extend_from_slice(&seq.to_be_bytes());
    data
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn table_replacement_takes_effect_while_traffic_flows() -> TestResult {
    let (mut a, mut b, translator) = pair().await?;
    let peer = a.peer_of(&b).await?;

    // A sender alternates between the old and the new `eam4` until told to stop.
    let stop = Arc::new(AtomicBool::new(false));
    let sender = {
        let local = a.local.clone();
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            for seq in 0..20_000_u32 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let new = seq % 2 == 1;
                let eam4 = if new { NEW_EAM4 } else { PEER_EAM4 };
                let packet = udp(v4(SELF_EAM4, 40020), v4(eam4, 5020), &tagged(new, seq));
                let mut buf = nsplane_packet::PacketBuf::with_capacity(packet.len() + 64);
                buf.set_len(packet.len());
                buf.as_packet_mut().copy_from_slice(&packet);
                if local.send(buf).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
    };

    // Every delivered packet is fully translated by one table or the other, never a mix:
    // only packets to the current `eam4` are translated (the other is native IPv4 that `b`
    // drops for its source), and each arrives with valid checksums.
    let mut seen = [0_u32; 2];
    let mut replaced = false;
    let deadline = tokio::time::Instant::now() + WAIT;
    while seen[1] == 0 {
        let got = tokio::time::timeout_at(deadline, async {
            expect_v6(&mut b, (SELF_EAM6, PEER_EAM6), protocol::UDP).await
        })
        .await
        .map_err(|_| "no packet to the new eam4 after the replacement")??;
        seen[usize::from(got[8])] += 1;
        if !replaced {
            translator.store(table(peer, NEW_EAM4)?);
            replaced = true;
        }
    }
    stop.store(true, Ordering::Relaxed);
    sender.await?;
    while let Ok(Some((_, packet))) = timeout(QUIET, b.delivered.recv()).await {
        verify_checksums(packet.as_packet())?;
        let (ip, _) = Ipv6Header::parse(packet.as_packet())?;
        assert_eq!((ip.src(), ip.dst()), (SELF_EAM6, PEER_EAM6));
    }
    assert!(seen[0] >= 1, "old eam4 translated before the replacement");

    // Now the old `eam4` is native IPv4 (dropped by `b`), the new one is translated, and
    // `b`'s replies come from the new `eam4`.
    a.send_with_room(&udp(v4(SELF_EAM4, 40021), v4(PEER_EAM4, 5021), b"old"))
        .await?;
    b.expect_no_delivery().await?;
    let request = udp(v4(SELF_EAM4, 40021), v4(NEW_EAM4, 5021), b"new");
    a.send_with_room(&request).await?;
    let got = expect_v6(&mut b, (SELF_EAM6, PEER_EAM6), protocol::UDP).await?;
    assert_same_segment(&got, &request, 6);
    let reply = udp(v6(PEER_EAM6, 5021), v6(SELF_EAM6, 40021), b"reply");
    b.send(&reply).await?;
    let got = expect_v4(&mut a, (NEW_EAM4, SELF_EAM4), protocol::UDP).await?;
    assert_same_segment(&got, &reply, 6);
    Ok(())
}
