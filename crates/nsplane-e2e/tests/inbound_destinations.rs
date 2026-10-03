//! Per-peer inbound destinations at engine level, over an in-memory channel transport: two
//! nodes `a` and `b`, where `b` restricts the destinations of `a`'s decrypted packets and `a`
//! routes `10.1.0.0/16` and `fd01::/64` to `b` besides `b`'s own addresses, so it can send to
//! destinations `b` does not own. The tests check deliveries and `Event::Dropped` reasons
//! while the set changes under the running engines through `add_or_update_peer` and
//! `set_inbound_destinations`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::{AllowedIp, ChannelTransport, Event, Peer, reasons};
use nsplane_e2e::{Events, Node, Options, TestResult, channel_pair, introduce, udp};

/// A destination `a` routes to `b` that `b` does not own.
const OTHER4: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 5);
const OTHER6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 5);
/// The port of every packet.
const PORT: u16 = 7000;

type ChannelNode = Node<ChannelTransport>;

fn cidr(s: &str) -> TestResult<AllowedIp> {
    Ok(s.parse()?)
}

/// A host prefix for `ip`.
const fn host(ip: IpAddr) -> AllowedIp {
    AllowedIp {
        addr: ip,
        cidr: if ip.is_ipv4() { 32 } else { 128 },
    }
}

/// Two peers linked like `channel_pair`; `b` knows `a` with `destinations`.
async fn pair(destinations: Option<Vec<AllowedIp>>) -> TestResult<(ChannelNode, ChannelNode)> {
    let (a, b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let mut to_b = b.as_peer(a.path.transport);
    to_b.allowed_ips
        .extend([cidr("10.1.0.0/16")?, cidr("fd01::/64")?]);
    a.handle.add_or_update_peer(to_b).await?;
    b.handle
        .add_or_update_peer(Peer {
            inbound_destinations: destinations,
            ..Peer::new(a.public())
        })
        .await?;
    Ok((a, b))
}

/// A UDP packet from `a`'s tunnel address of the family of `dst` to `dst`.
fn packet(a: &ChannelNode, dst: IpAddr) -> Vec<u8> {
    let src = match dst {
        IpAddr::V4(_) => IpAddr::V4(a.ip4),
        IpAddr::V6(_) => IpAddr::V6(a.ip6),
    };
    udp(
        SocketAddr::new(src, PORT),
        SocketAddr::new(dst, PORT),
        b"inbound",
    )
}

/// Sends a packet from `a` to `dst` and checks that `b` delivers it unchanged.
async fn delivered(a: &ChannelNode, b: &mut ChannelNode, dst: IpAddr) -> TestResult {
    let packet = packet(a, dst);
    a.send(&packet).await?;
    let (from, got) = b.expect_delivery().await?;
    if from != b.peer_of(a).await? || got != packet {
        return Err(format!("packet to {dst} changed in transit").into());
    }
    Ok(())
}

/// Sends a packet from `a` to `dst` and checks that `b` drops it as not allowed.
async fn dropped(
    a: &ChannelNode,
    b: &mut ChannelNode,
    events: &mut Events,
    dst: IpAddr,
) -> TestResult {
    let peer = b.peer_of(a).await?;
    a.send(&packet(a, dst)).await?;
    events
        .expect(|e| {
            matches!(e, Event::Dropped { peer: p, reason }
                if *p == Some(peer) && *reason == reasons::DESTINATION_NOT_ALLOWED)
        })
        .await?;
    b.expect_no_delivery().await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_peer_without_inbound_destinations_is_unchecked() -> TestResult {
    let (a, mut b) = pair(None).await?;
    for dst in [
        IpAddr::V4(b.ip4),
        IpAddr::V4(OTHER4),
        IpAddr::V6(b.ip6),
        IpAddr::V6(OTHER6),
    ] {
        delivered(&a, &mut b, dst).await?;
    }
    assert_eq!(b.drops(reasons::DESTINATION_NOT_ALLOWED).await?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn only_listed_destinations_pass_and_updates_replace_them() -> TestResult {
    let (b4, b6) = (
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V6("fd00::2".parse()?),
    );
    let (a, mut b) = pair(Some(vec![host(b4), host(b6)])).await?;
    let mut events = b.subscribe().await?;
    let (other4, other6) = (IpAddr::V4(OTHER4), IpAddr::V6(OTHER6));

    delivered(&a, &mut b, b4).await?;
    dropped(&a, &mut b, &mut events, other4).await?;
    delivered(&a, &mut b, b6).await?;
    dropped(&a, &mut b, &mut events, other6).await?;
    assert_eq!(b.drops(reasons::DESTINATION_NOT_ALLOWED).await?, 2);

    // An update with a new set replaces the old one.
    b.handle
        .add_or_update_peer(Peer {
            inbound_destinations: Some(vec![host(other4), host(other6)]),
            ..Peer::new(a.public())
        })
        .await?;
    delivered(&a, &mut b, other4).await?;
    dropped(&a, &mut b, &mut events, b4).await?;
    delivered(&a, &mut b, other6).await?;
    dropped(&a, &mut b, &mut events, b6).await?;

    // An update without one keeps it.
    b.handle
        .add_or_update_peer(a.as_peer(b.path.transport))
        .await?;
    delivered(&a, &mut b, other4).await?;
    dropped(&a, &mut b, &mut events, b4).await?;
    assert_eq!(b.drops(reasons::DESTINATION_NOT_ALLOWED).await?, 5);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_handle_sets_and_clears_inbound_destinations() -> TestResult {
    let (a, mut b) = pair(None).await?;
    let mut events = b.subscribe().await?;
    let (b4, other4, other6) = (IpAddr::V4(b.ip4), IpAddr::V4(OTHER4), IpAddr::V6(OTHER6));
    delivered(&a, &mut b, b4).await?;

    b.handle
        .set_inbound_destinations(a.public(), Some(vec![cidr("10.1.0.0/16")?]))
        .await?;
    dropped(&a, &mut b, &mut events, b4).await?;
    delivered(&a, &mut b, other4).await?;
    dropped(&a, &mut b, &mut events, other6).await?;

    b.handle
        .set_inbound_destinations(a.public(), Some(Vec::new()))
        .await?;
    dropped(&a, &mut b, &mut events, other4).await?;

    b.handle.set_inbound_destinations(a.public(), None).await?;
    for dst in [b4, other4, IpAddr::V6(b.ip6), other6] {
        delivered(&a, &mut b, dst).await?;
    }

    // A change for an unknown peer is ignored.
    b.handle
        .set_inbound_destinations(b.public(), Some(Vec::new()))
        .await?;
    delivered(&a, &mut b, b4).await?;
    assert_eq!(b.drops(reasons::DESTINATION_NOT_ALLOWED).await?, 3);
    Ok(())
}
