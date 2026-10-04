//! Datagrams built with `nsplane_packet::build` and injected into the tunnel: an in-tunnel
//! control message (IPv6 UDP to port 47900 between the node addresses, ns quick-v2 §9) on
//! the peer's current path with `EngineHandle::inject_outbound_on`, and an IPv4 one routed
//! with `EngineHandle::inject_outbound`, both delivered byte-identical with valid checksums.

use std::net::SocketAddr;

use nsplane_e2e::{
    Options, TestResult, channel_pair_with, exchange, introduce, payload, verify_checksums,
};
use nsplane_packet::udp_packet;

/// UDP port of ns's in-tunnel control channel.
const CONTROL_PORT: u16 = 47900;

#[tokio::test]
async fn built_datagrams_arrive_byte_identical() -> TestResult {
    let (mut a, mut b) = channel_pair_with(Options::default(), |_, builder| builder)?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    let to_b = a.peer_of(&b).await?;
    let from_a = b.peer_of(&a).await?;
    let path = a.handle.peer_stats(to_b).await?.ok_or("peer")?.path;

    let control = udp_packet(
        SocketAddr::from((a.ip6, CONTROL_PORT)),
        SocketAddr::from((b.ip6, CONTROL_PORT)),
        &payload(300),
    )?;
    let sent = control.as_packet().to_vec();
    a.handle
        .inject_outbound_on(to_b, path.ok_or("path")?, control)
        .await?;
    let (peer, delivered) = b.expect_delivery().await?;
    assert_eq!((peer, &delivered), (from_a, &sent));
    verify_checksums(&delivered)?;

    let datagram = udp_packet(
        SocketAddr::from((a.ip4, 5353)),
        SocketAddr::from((b.ip4, 53)),
        &payload(1001),
    )?;
    let sent = datagram.as_packet().to_vec();
    a.handle.inject_outbound(datagram).await?;
    let (peer, delivered) = b.expect_delivery().await?;
    assert_eq!((peer, &delivered), (from_a, &sent));
    verify_checksums(&delivered)?;
    Ok(())
}
