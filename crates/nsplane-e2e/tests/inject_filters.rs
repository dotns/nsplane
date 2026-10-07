//! The injection contract: packets injected with `EngineHandle::inject_outbound`,
//! `inject_outbound_on` and `inject_inbound` skip the engine's filters. Two nodes over an
//! in-memory channel transport, `a` with the filters: one that drops everything still lets
//! injected packets through in both directions, and an `AclFilter` whose inbound rules admit
//! nothing on their own admits the reply to a request `a` sent through it (reply state) but
//! not the replies to injected requests, which it never saw.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane::{ChannelTransport, Event, PacketFilter, PeerId};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, AclPolicy, Label, LabelSet, PeerLabelMap, reasons,
};
use nsplane_core::Verdict;
use nsplane_e2e::{
    Events, Node, Options, SharedFilter, TestResult, channel_pair_with, introduce, payload, udp,
};
use nsplane_packet::PacketBuf;

/// The drop reason of [`DropAll`].
const DROPPED: &str = "dropped by the test filter";

/// Drops every packet and counts the ones it saw.
#[derive(Debug, Default)]
struct DropAll {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

impl PacketFilter for DropAll {
    fn inbound(&self, _: PeerId, _: &mut PacketBuf) -> Verdict {
        self.inbound.fetch_add(1, Ordering::Relaxed);
        Verdict::Drop { reason: DROPPED }
    }

    fn outbound(&self, _: PeerId, _: &mut PacketBuf) -> Verdict {
        self.outbound.fetch_add(1, Ordering::Relaxed);
        Verdict::Drop { reason: DROPPED }
    }
}

const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

/// Checks that `to` delivers `packet` unchanged, from `from`.
async fn delivered(
    to: &mut Node<ChannelTransport>,
    from: &Node<ChannelTransport>,
    packet: &[u8],
) -> TestResult {
    let expected = (to.peer_of(from).await?, packet.to_vec());
    if to.expect_delivery().await? != expected {
        return Err("packet changed in transit".into());
    }
    Ok(())
}

/// Checks that `to` drops a packet with `reason` and delivers nothing.
async fn dropped(
    to: &mut Node<ChannelTransport>,
    events: &mut Events,
    reason: &'static str,
) -> TestResult {
    events
        .expect(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
        .await?;
    to.expect_no_delivery().await
}

#[tokio::test]
async fn injected_packets_skip_a_dropping_filter() -> TestResult {
    let filter = Arc::new(DropAll::default());
    let (mut a, mut b) = channel_pair_with(Options::default(), |seed, builder| {
        if seed == 1 {
            builder.filter(Box::new(SharedFilter(Arc::clone(&filter))))
        } else {
            builder
        }
    })?;
    introduce(&a, &b, None).await?;
    let mut events = a.subscribe().await?;
    let to_b = udp(v4(a.ip4, 6000), v4(b.ip4, 5000), &payload(100));
    let to_a = udp(v4(b.ip4, 5000), v4(a.ip4, 6000), &payload(100));

    a.send(&to_b).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == DROPPED))
        .await?;
    b.expect_no_delivery().await?;

    a.handle
        .inject_outbound(PacketBuf::from_packet(&to_b))
        .await?;
    delivered(&mut b, &a, &to_b).await?;
    let peer_b = a.peer_of(&b).await?;
    let path = a.handle.peer_stats(peer_b).await?.ok_or("peer")?.path;
    a.handle
        .inject_outbound_on(
            peer_b,
            path.ok_or("no path")?,
            PacketBuf::from_packet(&to_b),
        )
        .await?;
    delivered(&mut b, &a, &to_b).await?;

    b.send(&to_a).await?;
    dropped(&mut a, &mut events, DROPPED).await?;
    a.handle
        .inject_inbound(peer_b, PacketBuf::from_packet(&to_a))
        .await?;
    delivered(&mut a, &b, &to_a).await?;

    assert_eq!(filter.outbound.load(Ordering::Relaxed), 1);
    assert_eq!(filter.inbound.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn an_acl_keeps_no_reply_state_for_injected_packets() -> TestResult {
    let engine = Arc::new(AclEngine::new());
    let identities = Arc::new(PeerLabelMap::new());
    let filter = AclFilter::with_config(
        Arc::clone(&engine),
        Arc::clone(&identities),
        AclFilterConfig::default(),
    );
    let a_filter = filter.clone();
    let (mut a, mut b) = channel_pair_with(Options::default(), |seed, builder| {
        if seed == 1 {
            builder.filter(Box::new(a_filter.clone()))
        } else {
            builder
        }
    })?;
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;
    identities.insert(peer_b, LabelSet::new([Label::from("node-b")]));
    // Deny all: only reply state admits `b`'s packets.
    engine.load(AclPolicy::default())?;
    let mut events = a.subscribe().await?;
    let b_end = v4(b.ip4, 5000);

    // A request through the filter: its reply is admitted.
    let a_end = v4(a.ip4, 6000);
    a.send(&udp(a_end, b_end, b"request")).await?;
    delivered(&mut b, &a, &udp(a_end, b_end, b"request")).await?;
    let reply = udp(b_end, a_end, b"reply");
    b.send(&reply).await?;
    delivered(&mut a, &b, &reply).await?;

    // Injected requests: the filter never saw them, so their replies are denied.
    let path = a.handle.peer_stats(peer_b).await?.ok_or("peer")?.path;
    for (port, on_path) in [(6001, false), (6002, true)] {
        let a_end = v4(a.ip4, port);
        let request = udp(a_end, b_end, b"injected request");
        let packet = PacketBuf::from_packet(&request);
        if on_path {
            a.handle
                .inject_outbound_on(peer_b, path.ok_or("no path")?, packet)
                .await?;
        } else {
            a.handle.inject_outbound(packet).await?;
        }
        delivered(&mut b, &a, &request).await?;
        b.send(&udp(b_end, a_end, b"reply")).await?;
        dropped(&mut a, &mut events, reasons::DENIED).await?;
    }

    let stats = filter.stats();
    assert_eq!((stats.replies, stats.denied), (1, 2));
    Ok(())
}
