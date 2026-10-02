//! Runtime configuration through the engine handle: the allowed-IP source check and routing,
//! adding, updating and removing peers, paths, statistics, injection, forced handshakes and
//! shutdown.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, EngineError, Event, Peer};
use nsplane_e2e::{
    Family, Options, TestResult, WAIT, channel_pair, introduce, payload, transfer, udp_pair, udp4,
};
use nsplane_packet::{PacketBuf, Path};
use tokio::net::UdpSocket;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::timeout;

const SOURCE_NOT_ALLOWED: &str = "source not allowed";
const NO_ROUTE: &str = "no route";
/// A tunnel address no node owns.
const SPOOFED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 99);

const fn net(addr: Ipv4Addr, cidr: u8) -> AllowedIp {
    AllowedIp {
        addr: IpAddr::V4(addr),
        cidr,
    }
}

#[tokio::test]
async fn sources_outside_the_allowed_ips_are_dropped_until_they_are_allowed() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut events = a.subscribe().await?;

    // `b` routes the packet to `a`, but `a` only allows `b`'s own addresses as sources.
    b.send(&udp4(SPOOFED, a.ip4, b"spoofed")).await?;
    events
        .expect(|e| {
            matches!(e, Event::Dropped { peer: Some(p), reason } if *p == peer_b && *reason == SOURCE_NOT_ALLOWED)
        })
        .await?;
    a.expect_no_delivery().await?;
    assert_eq!(a.drops(SOURCE_NOT_ALLOWED).await?, 1);

    a.handle
        .set_allowed_ips(b.public(), vec![net(SPOOFED, 32)])
        .await?;
    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.allowed_ips, vec![net(SPOOFED, 32)]);

    // The new source is delivered, the old one is now dropped.
    let allowed = udp4(SPOOFED, a.ip4, b"allowed");
    b.send(&allowed).await?;
    assert_eq!(a.expect_delivery().await?, (peer_b, allowed));
    b.send(&b.packet_to(&a, Family::V4, b"old source")).await?;
    a.expect_no_delivery().await?;
    assert_eq!(a.drops(SOURCE_NOT_ALLOWED).await?, 2);

    // Outbound routing follows the new set.
    let routed = udp4(a.ip4, SPOOFED, b"routed");
    a.send(&routed).await?;
    let (from, delivered) = b.expect_delivery().await?;
    assert_eq!((from, delivered), (b.peer_of(&a).await?, routed));
    a.send(&a.packet_to(&b, Family::V4, b"no route")).await?;
    b.expect_no_delivery().await?;
    assert_eq!(a.drops(NO_ROUTE).await?, 1);
    Ok(())
}

#[tokio::test]
async fn add_or_update_peer_adds_or_replaces_allowed_ips() -> TestResult {
    let (mut a, b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;
    let first = Ipv4Addr::new(10, 1, 0, 7);
    let second = Ipv4Addr::new(10, 2, 0, 7);

    // Without `replace_allowed_ips`, the networks are added.
    a.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![net(Ipv4Addr::new(10, 1, 0, 0), 24)],
            ..Peer::new(b.public())
        })
        .await?;
    assert_eq!(a.peer_of(&b).await?, peer_b);
    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.allowed_ips.len(), 3);
    for packet in [udp4(b.ip4, a.ip4, b"own"), udp4(first, a.ip4, b"added")] {
        b.send(&packet).await?;
        assert_eq!(a.expect_delivery().await?, (peer_b, packet));
    }

    // With it, they replace the existing ones.
    a.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![net(Ipv4Addr::new(10, 2, 0, 0), 24)],
            replace_allowed_ips: true,
            ..Peer::new(b.public())
        })
        .await?;
    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.allowed_ips, vec![net(Ipv4Addr::new(10, 2, 0, 0), 24)]);
    let replaced = udp4(second, a.ip4, b"replaced");
    b.send(&replaced).await?;
    assert_eq!(a.expect_delivery().await?, (peer_b, replaced));
    for source in [b.ip4, first] {
        b.send(&udp4(source, a.ip4, b"removed")).await?;
        a.expect_no_delivery().await?;
    }
    assert_eq!(a.drops(SOURCE_NOT_ALLOWED).await?, 2);
    Ok(())
}

#[tokio::test]
async fn removed_peers_carry_no_traffic() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;

    a.handle.remove_peer(b.public()).await?;
    assert_eq!(a.handle.peer_id(b.public()).await?, None);
    assert_eq!(a.handle.peers().await?, Vec::new());

    a.send(&a.packet_to(&b, Family::V4, b"to nobody")).await?;
    b.expect_no_delivery().await?;
    assert_eq!(a.drops(NO_ROUTE).await?, 1);
    // `b` still holds a session, but `a` no longer knows it.
    b.send(&b.packet_to(&a, Family::V4, b"from nobody")).await?;
    a.expect_no_delivery().await?;
    Ok(())
}

#[tokio::test]
async fn remove_all_peers_empties_the_peer_list() -> TestResult {
    let (a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let other = PublicKey::from(&StaticSecret::from([9; 32]));
    a.handle.add_or_update_peer(Peer::new(other)).await?;
    assert_eq!(a.handle.peers().await?.len(), 2);

    a.handle.remove_all_peers().await?;
    assert_eq!(a.handle.peers().await?, Vec::new());
    assert_eq!(a.handle.peer_id(b.public()).await?, None);
    assert_eq!(a.handle.peer_id(other).await?, None);
    a.send(&a.packet_to(&b, Family::V4, b"to nobody")).await?;
    b.expect_no_delivery().await?;
    assert_eq!(a.drops(NO_ROUTE).await?, 1);
    Ok(())
}

#[tokio::test]
async fn set_path_redirects_outbound_datagrams() -> TestResult {
    let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (a, mut b) = udp_pair(localhost, Options::default())?;
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    let peer_b = a.peer_of(&b).await?;

    let elsewhere = UdpSocket::bind(SocketAddr::new(localhost, 0)).await?;
    let path = Path {
        transport: a.path.transport,
        addr: elsewhere.local_addr()?,
        ..b.path
    };
    a.handle.set_path(b.public(), path).await?;
    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.path, Some(path));

    a.send(&a.packet_to(&b, Family::V4, &payload(64))).await?;
    let mut buf = [0; 2048];
    let (len, from) = timeout(WAIT, elsewhere.recv_from(&mut buf)).await??;
    assert_eq!(from, a.path.addr);
    // A transport data message (type 4) with the 92-byte packet padded to 96 bytes.
    assert_eq!(buf[0], 4);
    assert_eq!(len, 16 + 96 + 16);
    b.expect_no_delivery().await?;

    a.handle
        .set_path(
            b.public(),
            b.as_peer(a.path.transport).path.ok_or("no path")?,
        )
        .await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    Ok(())
}

#[tokio::test]
async fn peer_stats_reflect_configuration_and_counters() -> TestResult {
    const PSK: [u8; 32] = [5; 32];
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;

    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.peer, peer_b);
    assert_eq!(stats.public_key, b.public());
    assert_eq!(
        stats.path,
        Some(Path {
            transport: a.path.transport,
            ..b.path
        })
    );
    let mut allowed_ips = stats.allowed_ips.clone();
    allowed_ips.sort();
    let mut expected = b.as_peer(a.path.transport).allowed_ips;
    expected.sort();
    assert_eq!(allowed_ips, expected);
    assert_eq!(stats.preshared_key, None);
    assert_eq!(stats.persistent_keepalive, None);
    assert_eq!((stats.rx, stats.tx, stats.data_rx), (0, 0, 0));
    assert_eq!(stats.last_handshake, None);

    // An update in place keeps the peer id.
    a.handle
        .add_or_update_peer(Peer {
            preshared_key: Some(PSK),
            ..Peer::new(b.public())
        })
        .await?;
    b.handle.set_preshared_key(a.public(), Some(PSK)).await?;
    assert_eq!(a.peer_of(&b).await?, peer_b);

    transfer(&a, &mut b, Family::V4, 100).await?;
    transfer(&b, &mut a, Family::V4, 200).await?;
    a.handle.set_keepalive(b.public(), Some(25)).await?;
    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.preshared_key, Some(PSK));
    assert_eq!(stats.persistent_keepalive, Some(25));
    assert_eq!(stats.data_rx, 20 + 8 + 200);
    // The tunnel counts the plaintext packets in both directions.
    assert_eq!((stats.rx, stats.tx), (20 + 8 + 200, 20 + 8 + 100));
    assert!(stats.last_handshake.is_some_and(|age| age < WAIT));
    let peers = a.handle.peers().await?;
    assert_eq!(
        peers
            .iter()
            .map(|s| (s.peer, s.public_key))
            .collect::<Vec<_>>(),
        vec![(peer_b, b.public())]
    );
    Ok(())
}

#[tokio::test]
async fn inject_inbound_delivers_as_the_peer() -> TestResult {
    let (mut a, b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;

    // Injection bypasses the allowed-IP source check.
    let packet = udp4(SPOOFED, a.ip4, b"injected");
    a.handle
        .inject_inbound(peer_b, PacketBuf::from_packet(&packet))
        .await?;
    assert_eq!(a.expect_delivery().await?, (peer_b, packet));
    assert_eq!(a.drops(SOURCE_NOT_ALLOWED).await?, 0);
    Ok(())
}

#[tokio::test]
async fn inject_outbound_is_encrypted_and_delivered_by_the_peer() -> TestResult {
    let (a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;

    let packet = a.packet_to(&b, Family::V6, &payload(300));
    a.handle
        .inject_outbound(PacketBuf::from_packet(&packet))
        .await?;
    assert_eq!(b.expect_delivery().await?, (b.peer_of(&a).await?, packet));
    Ok(())
}

#[tokio::test]
async fn force_handshake_completes_a_handshake_on_the_given_path() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    // `a` knows no path to `b` until the forced handshake gives it one.
    a.handle
        .add_or_update_peer(Peer {
            path: None,
            ..b.as_peer(a.path.transport)
        })
        .await?;
    b.handle
        .add_or_update_peer(a.as_peer(b.path.transport))
        .await?;
    let peer_b = a.peer_of(&b).await?;
    let path = b.as_peer(a.path.transport).path.ok_or("no path")?;
    let mut events = a.subscribe().await?;

    a.handle.force_handshake(peer_b, Some(path)).await?;
    events
        .expect(|e| {
            matches!(e, Event::HandshakeCompleted { peer, path: Some(p), .. } if *peer == peer_b && *p == path)
        })
        .await?;
    let stats = a.handle.peer_stats(peer_b).await?.ok_or("unknown peer")?;
    assert_eq!(stats.path, Some(path));
    assert!(stats.last_handshake.is_some());
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;

    // A second forced handshake rekeys the established session.
    a.handle.force_handshake(peer_b, None).await?;
    events
        .expect(|e| matches!(e, Event::HandshakeCompleted { peer, .. } if *peer == peer_b))
        .await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    Ok(())
}

#[tokio::test]
async fn shutdown_stops_the_engine() -> TestResult {
    let (a, b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let handle = a.handle.clone();
    let mut events = handle.subscribe().await?;

    handle.shutdown().await?;
    timeout(WAIT, a.engine.wait()).await??;
    assert!(matches!(handle.peers().await, Err(EngineError)));
    assert!(matches!(handle.peer_id(b.public()).await, Err(EngineError)));
    assert!(matches!(handle.shutdown().await, Err(EngineError)));
    assert!(matches!(
        handle.add_or_update_peer(Peer::new(b.public())).await,
        Err(EngineError)
    ));
    // Events published before the shutdown may still be queued.
    loop {
        match timeout(WAIT, events.recv()).await? {
            Err(RecvError::Closed) => return Ok(()),
            Ok(_) | Err(RecvError::Lagged(_)) => {}
        }
    }
}
