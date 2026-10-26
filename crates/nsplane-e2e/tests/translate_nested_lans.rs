//! Nested LAN prefixes through the `Translator` between three engines over channel
//! transports: node `a` runs IPv4-only applications and translates with
//! `TranslationTableBuilder::nested_lans`, nodes `g` and `p` are IPv6-only. `g` has the
//! default prefix 0.0.0.0/0 behind it under `G_LAN6::/96`, `p` the more specific
//! 10.1.0.0/16 under `P_LAN6::/96`, plus an `eam4` and a `peer6_eam4` that both lie inside
//! the /0. Covers the longest prefix and the exact addresses winning over UDP, TCP and ICMP
//! echo, and replies from `g` that claim an address of `p`'s LAN or an exact address under
//! the /0's base, which are dropped as unmapped. Every packet is checked by recomputing its
//! checksums in full where it arrives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::{ChannelTransport, EngineBuilder, PeerId, TransportId};
use nsplane_e2e::translate::{
    ACK, SELF_EAM4, SELF_EAM6, SYN, TestNode, allowed, assert_same_segment, expect_v4, expect_v6,
    lan6, v4, v6,
};
use nsplane_e2e::{Node, Options, SharedFilter, TestResult, icmp, payload, tcp, udp};
use nsplane_nat::translate::reasons;
use nsplane_nat::{LanPrefix, PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_packet::protocol;

/// `g`'s LAN: the default prefix 0.0.0.0/0, under a /96.
const G_LAN6: Ipv6Addr = Ipv6Addr::new(0xfd64, 0xa, 0, 0, 0, 0, 0, 0);
/// `p`'s LAN: 10.1.0.0/16 inside the /0, under a /96 of its own.
const P_LAN4: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 0);
const P_LAN6: Ipv6Addr = Ipv6Addr::new(0xfd64, 0xb, 0, 0, 0, 0, 0, 0);
/// `p`'s `peer6`, `eam6` and `a`'s exact IPv4 addresses for them, both inside the /0.
const P_PEER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 0);
const P_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 1);
const P_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const P_PEER6_EAM4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
/// A host of the /0 only, and a host of `p`'s /16.
const G_HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const P_HOST: Ipv4Addr = Ipv4Addr::new(10, 1, 2, 3);

/// Key seeds of the nodes.
const A_SEED: u8 = 1;
const G_SEED: u8 = 2;
const P_SEED: u8 = 3;
/// Capacity of the links.
const CAPACITY: usize = 1024;
/// `a`'s address on both links, and its transport ids for them.
const A_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000);
const A_TO_G: TransportId = TransportId::new(1);
const A_TO_P: TransportId = TransportId::new(3);
/// `g`'s and `p`'s transport ids and addresses.
const G_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);
const P_PATH: (TransportId, SocketAddr) = (
    TransportId::new(4),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 3000),
);

/// `a`'s nested table: its self mapping, `p`'s exact addresses, the /0 behind `g` and the
/// /16 behind `p`.
fn table(g: PeerId, p: PeerId) -> TestResult<TranslationTable> {
    Ok(TranslationTable::builder()
        .nested_lans()
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: SELF_EAM6,
        })
        .peer_with_peer6_eam4(
            p,
            PeerMapping {
                peer6: P_PEER6,
                eam6: P_EAM6,
                local6: None,
                eam4: Some(P_EAM4),
            },
            P_PEER6_EAM4,
        )
        .lan(LanPrefix {
            lan4: (Ipv4Addr::UNSPECIFIED, 0),
            lan6: (G_LAN6, 96),
            peer: Some(g),
        })
        .lan(LanPrefix {
            lan4: (P_LAN4, 16),
            lan6: (P_LAN6, 96),
            peer: Some(p),
        })
        .build()?)
}

/// Three peers: `a` translating with the table above, `g` and `p` IPv6-only.
///
/// `a` routes 0.0.0.0/0 and `G_LAN6::/96` to `g`, and 10.1.0.0/16, `P_LAN6::/96` and
/// `p`'s exact addresses to `p` (the core's allowed IPs are longest-match); `g` and `p`
/// route and accept `a`'s `eam6`.
async fn trio() -> TestResult<(TestNode, TestNode, TestNode, Arc<Translator>)> {
    // Placeholder peers until `g` and `p` have ids on `a`.
    let translator = Arc::new(Translator::new(table(
        PeerId::new(u32::MAX),
        PeerId::new(u32::MAX - 1),
    )?));
    let (a_g, g_a) = ChannelTransport::pair(CAPACITY, (A_TO_G, A_ADDR), G_PATH);
    let (a_p, p_a) = ChannelTransport::pair(CAPACITY, (A_TO_P, A_ADDR), P_PATH);
    let a = Node::with_builder(A_SEED, A_TO_G, A_ADDR, Options::default(), |builder| {
        [a_g, a_p].into_iter().fold(
            builder.filter(Box::new(SharedFilter(Arc::clone(&translator)))),
            EngineBuilder::transport,
        )
    })?;
    let g = Node::new(G_SEED, G_PATH.0, G_PATH.1, g_a, Options::default());
    let p = Node::new(P_SEED, P_PATH.0, P_PATH.1, p_a, Options::default());

    let g_ips = vec![allowed(Ipv4Addr::UNSPECIFIED, 0), allowed(G_LAN6, 96)];
    let p_ips = vec![
        allowed(P_LAN4, 16),
        allowed(P_LAN6, 96),
        allowed(P_EAM4, 32),
        allowed(P_PEER6_EAM4, 32),
        allowed(P_EAM6, 128),
        allowed(P_PEER6, 128),
    ];
    for (node, via, ips) in [(&g, A_TO_G, g_ips), (&p, A_TO_P, p_ips)] {
        let mut peer = node.as_peer(via);
        peer.allowed_ips = ips;
        a.handle.add_or_update_peer(peer).await?;
        let mut peer = a.as_peer(node.path.transport);
        peer.allowed_ips = vec![allowed(SELF_EAM6, 128)];
        node.handle.add_or_update_peer(peer).await?;
    }
    translator.store(table(a.peer_of(&g).await?, a.peer_of(&p).await?)?);
    Ok((a, g, p, translator))
}

#[tokio::test]
async fn the_longest_prefix_and_the_exact_addresses_win() -> TestResult {
    let (mut a, mut g, mut p, translator) = trio().await?;
    let rest = [0x12, 0x34, 0, 1];
    let data = payload(56);
    // (IPv4 destination of `a`'s app, IPv6 address its owner sees, owner is `g`).
    let targets = [
        (G_HOST, lan6(G_LAN6, G_HOST), true),
        (P_HOST, lan6(P_LAN6, P_HOST), false),
        (P_EAM4, P_EAM6, false),
        (P_PEER6_EAM4, P_PEER6, false),
    ];
    for (dst4, dst6, to_g) in targets {
        let node = if to_g { &mut g } else { &mut p };

        // UDP.
        let request = udp(v4(SELF_EAM4, 42001), v4(dst4, 7001), &payload(300));
        a.send_with_room(&request).await?;
        let got = expect_v6(node, (SELF_EAM6, dst6), protocol::UDP).await?;
        assert_same_segment(&got, &request, 6);
        let reply = udp(v6(dst6, 7001), v6(SELF_EAM6, 42001), &payload(700));
        node.send(&reply).await?;
        let got = expect_v4(&mut a, (dst4, SELF_EAM4), protocol::UDP).await?;
        assert_same_segment(&got, &reply, 6);

        // A TCP handshake.
        let syn = tcp(v4(SELF_EAM4, 42002), v4(dst4, 80), SYN, (100, 0), &[]);
        a.send_with_room(&syn).await?;
        let got = expect_v6(node, (SELF_EAM6, dst6), protocol::TCP).await?;
        assert_same_segment(&got, &syn, 16);
        let syn_ack = tcp(
            v6(dst6, 80),
            v6(SELF_EAM6, 42002),
            SYN | ACK,
            (200, 101),
            &[],
        );
        node.send(&syn_ack).await?;
        let got = expect_v4(&mut a, (dst4, SELF_EAM4), protocol::TCP).await?;
        assert_same_segment(&got, &syn_ack, 16);

        // ICMP echo.
        let request = icmp(SELF_EAM4.into(), dst4.into(), (8, 0), rest, &data);
        a.send_with_room(&request).await?;
        let got = expect_v6(node, (SELF_EAM6, dst6), protocol::ICMPV6).await?;
        assert_eq!(got[..2], [128, 0]);
        assert_eq!(got[4..8], rest);
        assert_eq!(got[8..], data);
        let reply = icmp(dst6.into(), SELF_EAM6.into(), (129, 0), rest, &data);
        node.send(&reply).await?;
        let got = expect_v4(&mut a, (dst4, SELF_EAM4), protocol::ICMP).await?;
        assert_eq!(got[..2], [0, 0]);
        assert_eq!(got[4..8], rest);
        assert_eq!(got[8..], data);
    }

    let stats = translator.stats();
    let packets = 3 * 4;
    assert_eq!(
        (stats.translated_out, stats.translated_in),
        (packets, packets)
    );
    assert_eq!((stats.dropped_out, stats.dropped_in), (0, 0));
    Ok(())
}

#[tokio::test]
async fn spoofed_replies_under_the_default_prefix_are_dropped() -> TestResult {
    let (mut a, g, _p, translator) = trio().await?;
    // `g` claims, under its /0's base, an address of `p`'s /16 and the exact addresses.
    let spoofs = [P_HOST, P_EAM4, P_PEER6_EAM4];
    for host in spoofs {
        let src = lan6(G_LAN6, host);
        g.send(&udp(v6(src, 7010), v6(SELF_EAM6, 42010), &payload(64)))
            .await?;
        a.expect_no_delivery().await?;
    }
    let sent = u64::try_from(spoofs.len())?;
    let stats = translator.stats();
    assert_eq!((stats.translated_in, stats.dropped_in), (0, sent));
    assert_eq!(a.drops(reasons::UNMAPPED).await?, sent);

    // An address of the /0 only still gets through.
    let reply = udp(
        v6(lan6(G_LAN6, G_HOST), 7010),
        v6(SELF_EAM6, 42010),
        &payload(64),
    );
    g.send(&reply).await?;
    let got = expect_v4(&mut a, (G_HOST, SELF_EAM4), protocol::UDP).await?;
    assert_same_segment(&got, &reply, 6);
    let stats = translator.stats();
    assert_eq!((stats.translated_in, stats.dropped_in), (1, sent));
    Ok(())
}
