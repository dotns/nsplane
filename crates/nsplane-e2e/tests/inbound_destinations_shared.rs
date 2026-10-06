//! Caller-updated inbound destinations at engine level, over an in-memory channel transport:
//! two nodes `a` and `b`, where `b` checks the destinations of `a`'s decrypted packets against
//! a grant snapshot it owns and `a` routes `10.1.0.0/16` to `b` besides `b`'s own addresses.
//! The caller revokes and grants destinations in its snapshot only, with no handle call in
//! between, and the next packet follows the change, with and without crypto workers.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use nsplane::{AllowedIp, ChannelTransport, Event, InboundDestinations, reasons};
use nsplane_e2e::{Events, Node, Options, TestResult, channel_pair_with, introduce, udp};

/// Destinations `a` routes to `b` that `b` does not own.
const OTHER: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 5);
const LATER: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 6);
/// The port of every packet.
const PORT: u16 = 7000;

type ChannelNode = Node<ChannelTransport>;

/// The caller's grant snapshot: the destinations it allows.
#[derive(Default)]
struct Grants(RwLock<HashSet<IpAddr>>);

impl Grants {
    fn set(&self, dst: Ipv4Addr, granted: bool) {
        let mut grants = self.0.write().unwrap_or_else(PoisonError::into_inner);
        if granted {
            grants.insert(IpAddr::V4(dst));
        } else {
            grants.remove(&IpAddr::V4(dst));
        }
    }
}

impl InboundDestinations for Grants {
    fn allows(&self, dst: IpAddr) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&dst)
    }
}

/// Two peers linked like `channel_pair`, with `workers` crypto workers each; `b` checks `a`
/// against `grants`.
async fn pair(grants: &Arc<Grants>, workers: usize) -> TestResult<(ChannelNode, ChannelNode)> {
    let (a, b) = channel_pair_with(Options::default(), |_, builder| {
        builder.crypto_workers(workers)
    })?;
    introduce(&a, &b, None).await?;
    let mut to_b = b.as_peer(a.path.transport);
    to_b.allowed_ips.push("10.1.0.0/16".parse::<AllowedIp>()?);
    a.handle.add_or_update_peer(to_b).await?;
    let source: Arc<dyn InboundDestinations> = Arc::clone(grants) as _;
    b.handle
        .set_inbound_destination_source(a.public(), Some(source))
        .await?;
    Ok((a, b))
}

/// A UDP packet from `a`'s tunnel address to `dst`.
fn packet(a: &ChannelNode, dst: Ipv4Addr) -> Vec<u8> {
    udp(
        SocketAddr::new(IpAddr::V4(a.ip4), PORT),
        SocketAddr::new(IpAddr::V4(dst), PORT),
        b"inbound",
    )
}

/// Sends a packet from `a` to `dst` and checks that `b` delivers it unchanged.
async fn delivered(a: &ChannelNode, b: &mut ChannelNode, dst: Ipv4Addr) -> TestResult {
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
    dst: Ipv4Addr,
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
async fn the_next_packet_follows_the_callers_snapshot() -> TestResult {
    next_packet_follows_the_snapshot(0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_next_packet_follows_the_callers_snapshot_with_crypto_workers() -> TestResult {
    next_packet_follows_the_snapshot(2).await
}

async fn next_packet_follows_the_snapshot(workers: usize) -> TestResult {
    let grants = Arc::new(Grants::default());
    grants.set(OTHER, true);
    let (a, mut b) = pair(&grants, workers).await?;
    let mut events = b.subscribe().await?;
    let own = b.ip4;

    delivered(&a, &mut b, OTHER).await?;
    dropped(&a, &mut b, &mut events, LATER).await?;
    dropped(&a, &mut b, &mut events, own).await?;

    // A revoked grant drops the next packet, a new one admits it.
    grants.set(OTHER, false);
    dropped(&a, &mut b, &mut events, OTHER).await?;
    grants.set(LATER, true);
    delivered(&a, &mut b, LATER).await?;
    grants.set(OTHER, true);
    delivered(&a, &mut b, OTHER).await?;
    assert_eq!(b.drops(reasons::DESTINATION_NOT_ALLOWED).await?, 3);

    // An owned list replaces the source, and removing it leaves the peer unchecked.
    b.handle
        .set_inbound_destinations(a.public(), Some(Vec::new()))
        .await?;
    dropped(&a, &mut b, &mut events, OTHER).await?;
    b.handle
        .set_inbound_destination_source(a.public(), None)
        .await?;
    delivered(&a, &mut b, own).await?;
    assert_eq!(b.drops(reasons::DESTINATION_NOT_ALLOWED).await?, 4);
    Ok(())
}
