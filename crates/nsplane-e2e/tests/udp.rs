//! Two engines over UDP on the loopback interface, and roaming to a new source address.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::{Event, UdpTransport};
use nsplane_e2e::{Family, Options, TestResult, exchange, introduce, transfer, udp_pair};

#[tokio::test]
async fn exchange_over_ipv4_loopback() -> TestResult {
    let (mut a, mut b) = udp_pair(IpAddr::V4(Ipv4Addr::LOCALHOST), Options::default())?;
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await
}

#[tokio::test]
async fn exchange_over_ipv6_loopback() -> TestResult {
    let (mut a, mut b) = match udp_pair(IpAddr::V6(Ipv6Addr::LOCALHOST), Options::default()) {
        Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
            writeln!(io::stderr(), "skipped: cannot bind [::1]: {e}")?;
            return Ok(());
        }
        nodes => nodes?,
    };
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await
}

#[tokio::test]
async fn standard_roaming_follows_a_new_source_address() -> TestResult {
    let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (mut a, mut b) = udp_pair(localhost, Options::default())?;
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    let peer = a.peer_of(&b).await?;
    let mut events = a.subscribe().await?;

    // `b` moves to a new socket; `a` keeps its own.
    let moved = UdpTransport::bind(b.path.transport, SocketAddr::new(localhost, 0))?;
    let new_addr = moved.local_addr();
    assert_ne!(new_addr, b.path.addr);
    b.handle.set_transport(moved).await?;

    transfer(&b, &mut a, Family::V4, 64).await?;
    events
        .expect(|e| {
            matches!(e, Event::PathAdopted { peer: p, path }
                if *p == peer && path.addr == new_addr && path.transport == a.path.transport)
        })
        .await?;
    let stats = a.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
    assert_eq!(stats.path.map(|path| path.addr), Some(new_addr));

    // Replies follow the new path.
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&a, &mut b, Family::V6, 1300).await?;
    Ok(())
}
