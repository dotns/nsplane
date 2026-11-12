//! Fragments and IPv6 extension headers addressed to a route are dropped
//! with a reason of their own instead of passing untranslated.

use super::*;

/// Asserts that `call` drops `packet` for `reason` without changing it.
fn assert_drop(
    mut packet: PacketBuf,
    reason: &'static str,
    call: impl Fn(&mut PacketBuf) -> Nat64Verdict,
) {
    let before = packet.as_packet().to_vec();
    assert_eq!(call(&mut packet), Nat64Verdict::Drop(reason));
    assert_eq!(packet.as_packet(), before.as_slice());
}

/// An IPv6 packet from `CLIENT` to `dst` whose first next header is `next`,
/// an 8-byte extension header leading to UDP.
fn extended(next: u8, dst: Ipv6Addr) -> PacketBuf {
    let mut body = vec![protocol::UDP, 0, 0, 0, 0, 0, 0, 1];
    body.extend_from_slice(&udp(4321, 53, b"query"));
    PacketBuf::from_packet(&ipv6_bytes(next, CLIENT, dst, body))
}

/// An IPv4 fragment of a UDP datagram from `src` to `dst` with the flags and
/// fragment offset word `fragment`.
fn fragment4(src: Ipv4Addr, dst: Ipv4Addr, fragment: u16) -> PacketBuf {
    let mut packet = ipv4_bytes(protocol::UDP, src, dst, udp(53, 40_000, &[7; 16]));
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[10..12].fill(0);
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    PacketBuf::from_packet(&packet)
}

#[test]
fn ipv6_fragments_to_a_route_are_dropped() {
    let lan = lan();
    assert_drop(extended(44, HOST6), reasons::FRAGMENT, |p| lan.forward(p));
    assert_eq!(lan.fragment_drops(), 1);
    // The address need not resolve: the mapped prefix is the translator's.
    let unsafe_target = mapped(Ipv4Addr::new(192, 168, 7, 255));
    assert_drop(extended(44, unsafe_target), reasons::FRAGMENT, |p| {
        lan.forward(p)
    });
    assert_eq!(lan.fragment_drops(), 2);
    let stats = lan.stats();
    assert_eq!(
        (stats.not_ours, stats.other_drops, stats.forwarded),
        (0, 0, 0)
    );
    assert_eq!(stats.conntrack.entries, 0);
}

#[test]
fn ipv6_extension_headers_to_a_route_are_dropped() {
    let lan = lan();
    // Hop-by-hop options, routing, destination options.
    for next in [0, 43, 60] {
        assert_drop(extended(next, HOST6), reasons::EXTENSION_HEADER, |p| {
            lan.forward(p)
        });
    }
    assert_eq!(lan.extension_header_drops(), 3);
    assert_eq!(lan.fragment_drops(), 0);
    assert_eq!(lan.stats().other_drops, 0);
}

#[test]
fn ipv6_fragments_and_extension_headers_elsewhere_are_not_ours() {
    let lan = lan();
    let other = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 8, 0xc0a8, 0x0701);
    for next in [0, 43, 44, 60] {
        assert_not_ours(&mut extended(next, other), |p| lan.forward(p));
    }
    assert_eq!(lan.stats().not_ours, 4);
    assert_eq!((lan.fragment_drops(), lan.extension_header_drops()), (0, 0));
}

#[test]
fn ipv4_fragments_from_the_lan_to_the_snat_source_are_dropped() {
    let lan = lan();
    // A first fragment (MF), a later one (an offset), and a last one of an
    // unknown flow: without ports the flow cannot be told, so none passes.
    for fragment in [0x2000, 0x2003, 0x0003] {
        assert_drop(fragment4(HOST, SNAT, fragment), reasons::FRAGMENT, |p| {
            lan.reverse(p)
        });
    }
    assert_eq!(lan.fragment_drops(), 3);
    let stats = lan.stats();
    assert_eq!(
        (stats.not_ours, stats.other_drops, stats.reversed),
        (0, 0, 0)
    );
}

#[test]
fn other_ipv4_fragments_are_not_ours() {
    let lan = lan();
    // To another address, and to the SNAT source from outside the LAN.
    let elsewhere = Ipv4Addr::new(192, 168, 7, 9);
    assert_not_ours(&mut fragment4(HOST, elsewhere, 0x2000), |p| lan.reverse(p));
    let outside = Ipv4Addr::new(10, 0, 0, 1);
    assert_not_ours(&mut fragment4(outside, SNAT, 0x2000), |p| lan.reverse(p));
    // DF alone is no fragment: the packet is a reply of an unknown flow.
    assert_not_ours(&mut fragment4(HOST, SNAT, 0x4000), |p| lan.reverse(p));
    assert_eq!(lan.fragment_drops(), 0);
}

#[tokio::test]
async fn the_wrappers_discard_untranslatable_packets() {
    let nat = Arc::new(lan());
    let inner = SpentSink::default();
    let sink = Nat64LanSink::new(inner.clone(), Arc::clone(&nat));
    sink.send(extended(44, HOST6), PeerId::new(1))
        .await
        .unwrap();
    sink.send(extended(60, HOST6), PeerId::new(1))
        .await
        .unwrap();
    assert!(inner.0.lock().unwrap().is_empty());
    assert_eq!((nat.fragment_drops(), nat.extension_header_drops()), (1, 1));
}
