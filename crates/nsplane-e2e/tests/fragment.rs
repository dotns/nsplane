//! The engine's fragmentation stage between two engines over a channel transport: Packet Too
//! Big and Fragmentation Needed delivered to the sender, native IPv4 keeping the full MTU,
//! IPv4 fragments translated to IPv6 fragments by a `Translator`, MTU changes, and no stage
//! without `EngineBuilder::fragmenter`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use nsplane::{
    AllowedIp, ChannelTransport, Event, FragmentConfig, PacketBuf, PacketFilter, PeerId,
};
use nsplane_core::Verdict;
use nsplane_e2e::{
    Family, MTU, Node, Options, TestResult, channel_pair, channel_pair_with, introduce, payload,
    transfer, udp4, udp6,
};
use nsplane_nat::{PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_packet::checksum::{internet_checksum, ipv4_header_checksum, transport_checksum_v6};
use nsplane_packet::{Ipv4Header, Ipv6Header, protocol};

/// Node 1's own IPv4 address, translated to and from `SELF_NODE4`.
const SELF4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
const SELF_NODE4: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);
/// Node 2's /127 group and node 1's IPv4 alias for it.
const PEER_NODE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 0);
const PEER_NODE4: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 1);
const PEER_ALIAS4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

/// Next header value of the IPv6 Fragment header.
const IPV6_FRAGMENT: u8 = 44;

/// A translator shared between the engine and the test, which fills in its table once the
/// peer has an id.
struct Shared(Arc<Translator>);

impl PacketFilter for Shared {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.inbound(peer, packet)
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.outbound(peer, packet)
    }
}

fn table(peer: Option<PeerId>) -> TestResult<TranslationTable> {
    let mut builder = TranslationTable::builder().self_mapping(SelfMapping {
        self4: SELF4,
        node4: SELF_NODE4,
    });
    if let Some(peer) = peer {
        builder = builder.peer(
            peer,
            PeerMapping {
                node6: PEER_NODE6,
                node4: PEER_NODE4,
                alias6: None,
                alias4: Some(PEER_ALIAS4),
            },
        );
    }
    Ok(builder.build()?)
}

fn allowed(addr: impl Into<IpAddr>, cidr: u8) -> AllowedIp {
    AllowedIp {
        addr: addr.into(),
        cidr,
    }
}

/// Two peers with a fragmenter on node 1 (the IPv4 side) and none on node 2 (the IPv6
/// side); with `translate`, node 1 also translates node 2's IPv4 alias.
async fn pair(
    translate: bool,
) -> TestResult<(
    Node<ChannelTransport>,
    Node<ChannelTransport>,
    Option<Arc<Translator>>,
)> {
    let translator = translate.then(|| table(None).map(|t| Arc::new(Translator::new(t))));
    let translator = translator.transpose()?;
    let shared = translator.clone();
    let (a, b) = channel_pair_with(Options::default(), |seed, builder| match (seed, &shared) {
        (1, Some(translator)) => builder
            .filter(Box::new(Shared(Arc::clone(translator))))
            .fragmenter(FragmentConfig {
                translated: Some(translator.ipv4_translated_predicate()),
            }),
        (1, None) => builder.fragmenter(FragmentConfig::default()),
        _ => builder,
    })?;
    introduce(&a, &b, None).await?;
    if let Some(translator) = &translator {
        // Node 1 routes the alias to node 2; node 2 accepts node 1's translated source.
        let mut peer = b.as_peer(a.path.transport);
        peer.allowed_ips = vec![allowed(PEER_ALIAS4, 32), allowed(PEER_NODE4, 128)];
        a.handle.add_or_update_peer(peer).await?;
        let mut peer = a.as_peer(b.path.transport);
        peer.allowed_ips = vec![allowed(SELF_NODE4, 128)];
        b.handle.add_or_update_peer(peer).await?;
        translator.store(table(Some(a.peer_of(&b).await?))?);
    }
    Ok((a, b, translator))
}

/// Hands `packet` to `node` in a buffer with room for the translation to grow it, as a
/// TUN source's buffers have.
async fn send_with_room(node: &Node<ChannelTransport>, packet: &[u8]) -> TestResult {
    let mut buf = PacketBuf::with_capacity(packet.len() + 64);
    buf.set_len(packet.len());
    buf.as_packet_mut().copy_from_slice(packet);
    node.local.send(buf).await?;
    Ok(())
}

/// `packet` with DF cleared and the header checksum fixed.
fn without_df(mut packet: Vec<u8>) -> Vec<u8> {
    packet[6] &= !0x40;
    let sum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// Checks that `node` received an `ICMPv6` Packet Too Big about `original` carrying `mtu`.
async fn expect_packet_too_big(
    node: &mut Node<ChannelTransport>,
    from: PeerId,
    original: &[u8],
    mtu: u16,
) -> TestResult {
    let (peer, reply) = node.expect_delivery().await?;
    assert_eq!(peer, from);
    let (orig, _) = Ipv6Header::parse(original)?;
    let (header, icmp) = Ipv6Header::parse(&reply)?;
    assert_eq!((header.src(), header.dst()), (orig.dst(), orig.src()));
    assert_eq!(header.next_header(), protocol::ICMPV6);
    assert_eq!((icmp[0], icmp[1]), (2, 0));
    assert_eq!(icmp[4..8], u32::from(mtu).to_be_bytes());
    assert_eq!(
        transport_checksum_v6(header.src(), header.dst(), protocol::ICMPV6, icmp),
        0
    );
    let quoted = original.len().min(1232);
    assert_eq!(icmp[8..], original[..quoted]);
    Ok(())
}

/// Checks that `node` received an ICMP Fragmentation Needed about `original` carrying `mtu`.
async fn expect_fragmentation_needed(
    node: &mut Node<ChannelTransport>,
    from: PeerId,
    original: &[u8],
    mtu: u16,
) -> TestResult {
    let (peer, reply) = node.expect_delivery().await?;
    assert_eq!(peer, from);
    let (orig, _) = Ipv4Header::parse(original)?;
    let (header, icmp) = Ipv4Header::parse(&reply)?;
    assert_eq!((header.src(), header.dst()), (orig.dst(), orig.src()));
    assert_eq!(header.protocol(), protocol::ICMP);
    assert_eq!(internet_checksum(&reply[..20]), 0);
    assert_eq!((icmp[0], icmp[1]), (3, 4));
    assert_eq!(icmp[6..8], mtu.to_be_bytes());
    assert_eq!(internet_checksum(icmp), 0);
    assert_eq!(icmp[8..], original[..icmp.len() - 8]);
    Ok(())
}

#[tokio::test]
async fn oversized_ipv6_is_answered_with_packet_too_big() -> TestResult {
    let (mut a, mut b, _) = pair(false).await?;
    let from_b = a.peer_of(&b).await?;

    let packet = udp6(a.ip6, b.ip6, &payload(1500));
    a.send(&packet).await?;
    expect_packet_too_big(&mut a, from_b, &packet, MTU).await?;
    b.expect_no_delivery().await?;

    // At the MTU, the packet goes through.
    let fits = udp6(a.ip6, b.ip6, &payload(usize::from(MTU) - 48));
    a.send(&fits).await?;
    assert_eq!(b.expect_delivery().await?.1, fits);
    a.expect_no_delivery().await?;
    Ok(())
}

#[tokio::test]
async fn oversized_ipv4_with_df_is_answered_with_fragmentation_needed() -> TestResult {
    let (mut a, mut b, _) = pair(false).await?;
    let from_b = a.peer_of(&b).await?;

    let packet = udp4(a.ip4, b.ip4, &payload(1500));
    a.send(&packet).await?;
    expect_fragmentation_needed(&mut a, from_b, &packet, MTU).await?;
    b.expect_no_delivery().await?;
    Ok(())
}

#[tokio::test]
async fn native_ipv4_keeps_the_full_mtu() -> TestResult {
    let (mut a, mut b, _translator) = pair(true).await?;
    let from_b = a.peer_of(&b).await?;

    // A native destination: the predicate is false, so the whole MTU is usable.
    let native = udp4(a.ip4, b.ip4, &payload(usize::from(MTU) - 28));
    a.send(&native).await?;
    assert_eq!(b.expect_delivery().await?.1, native);

    // The same size to the translated alias is 20 bytes too large once it is IPv6.
    let translated = udp4(SELF4, PEER_ALIAS4, &payload(usize::from(MTU) - 28));
    a.send(&translated).await?;
    expect_fragmentation_needed(&mut a, from_b, &translated, MTU - 20).await?;
    b.expect_no_delivery().await?;

    // 20 bytes less fits as one IPv6 packet of exactly the MTU.
    let fits = udp4(SELF4, PEER_ALIAS4, &payload(usize::from(MTU) - 48));
    send_with_room(&a, &fits).await?;
    let (_, delivered) = b.expect_delivery().await?;
    assert_eq!(delivered.len(), usize::from(MTU));
    assert_eq!(Ipv6Header::parse(&delivered)?.0.dst(), PEER_NODE4);
    Ok(())
}

/// Reassembles the IPv6 fragments `node` receives into the unfragmented packet.
async fn reassemble(node: &mut Node<ChannelTransport>) -> TestResult<Vec<u8>> {
    let mut header = None;
    let mut payload = Vec::new();
    loop {
        let (_, fragment) = node.expect_delivery().await?;
        assert!(
            fragment.len() <= usize::from(MTU),
            "{} > {MTU}",
            fragment.len()
        );
        let (ip, body) = Ipv6Header::parse(&fragment)?;
        assert_eq!(ip.next_header(), IPV6_FRAGMENT);
        let field = u16::from_be_bytes([body[2], body[3]]);
        assert_eq!(usize::from(field & !7), payload.len(), "fragments in order");
        payload.extend_from_slice(&body[8..]);
        if header.is_none() {
            let mut first = fragment[..40].to_vec();
            first[6] = body[0];
            header = Some(first);
        }
        if field & 1 == 0 {
            break;
        }
        assert_eq!(body[8..].len() % 8, 0);
    }
    let mut packet = header.ok_or("no fragment")?;
    packet[4..6].copy_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    packet.extend_from_slice(&payload);
    Ok(packet)
}

#[tokio::test]
async fn translated_ipv4_arrives_as_ipv6_fragments() -> TestResult {
    let (a, mut b, translator) = pair(true).await?;
    let translator = translator.ok_or("no translator")?;
    let data = payload(4000);
    let original = udp4(SELF4, PEER_ALIAS4, &data);

    for zero_checksum in [false, true] {
        let mut packet = without_df(original.clone());
        if zero_checksum {
            packet[26..28].fill(0);
        }
        a.send(&packet).await?;

        let reassembled = reassemble(&mut b).await?;
        let (ip, udp) = Ipv6Header::parse(&reassembled)?;
        assert_eq!((ip.src(), ip.dst()), (SELF_NODE4, PEER_NODE4));
        assert_eq!(ip.next_header(), protocol::UDP);
        assert_eq!(ip.hop_limit(), 63);
        assert_eq!(udp[..6], original[20..26]);
        assert_eq!(udp[8..], data);
        // A valid checksum over the IPv6 pseudo-header, also when the IPv4 datagram had none.
        assert_eq!(
            transport_checksum_v6(SELF_NODE4, PEER_NODE4, protocol::UDP, udp),
            0,
            "zero checksum: {zero_checksum}"
        );
    }
    // Every fragment was translated on its own: nothing waited for reassembly.
    assert_eq!(translator.stats().reassembled, 0);
    Ok(())
}

#[tokio::test]
async fn an_mtu_change_moves_the_threshold() -> TestResult {
    let (mut a, mut b, _) = pair(false).await?;
    let from_b = a.peer_of(&b).await?;
    let mut events = a.subscribe().await?;
    let packet = udp6(a.ip6, b.ip6, &payload(1300));

    a.send(&packet).await?;
    assert_eq!(b.expect_delivery().await?.1, packet);

    a.mtu.send(1280)?;
    events
        .expect(|e| matches!(e, Event::MtuChanged { mtu: 1280 }))
        .await?;
    a.send(&packet).await?;
    expect_packet_too_big(&mut a, from_b, &packet, 1280).await?;
    b.expect_no_delivery().await?;

    let ipv4 = without_df(udp4(a.ip4, b.ip4, &payload(1300)));
    a.send(&ipv4).await?;
    let (_, first) = b.expect_delivery().await?;
    let (_, second) = b.expect_delivery().await?;
    assert_eq!(first.len(), 1276);
    assert_eq!(second.len(), 20 + 1308 - 1256);
    Ok(())
}

#[tokio::test]
async fn without_a_fragmenter_oversized_packets_go_through() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;

    for packet in [
        udp6(a.ip6, b.ip6, &payload(3000)),
        udp4(a.ip4, b.ip4, &payload(3000)),
    ] {
        a.send(&packet).await?;
        assert_eq!(b.expect_delivery().await?.1, packet);
    }
    a.expect_no_delivery().await?;
    Ok(())
}

#[tokio::test]
async fn errors_need_a_route() -> TestResult {
    let (mut a, mut b, _) = pair(false).await?;
    // No peer has 10.9.9.9 in its allowed IPs: no route, no error, nothing sent.
    let packet = udp4(a.ip4, Ipv4Addr::new(10, 9, 9, 9), &payload(1500));
    a.send(&packet).await?;
    a.expect_no_delivery().await?;
    b.expect_no_delivery().await?;
    Ok(())
}
