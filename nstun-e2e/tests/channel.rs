//! Two engines over an in-memory channel transport: handshake, IPv4 and IPv6 in both
//! directions, large packets and preshared keys.

use nstun::Event;
use nstun_e2e::{Family, Options, TestResult, channel_pair, introduce, introduce_with, transfer};

const PSK: [u8; 32] = [7; 32];

#[tokio::test]
async fn handshake_completes() -> TestResult {
    let (a, mut b) = channel_pair(Options::default());
    let mut events = a.subscribe().await?;
    introduce(&a, &b, None).await?;
    let peer = a.peer_of(&b).await?;

    transfer(&a, &mut b, Family::V4, 64).await?;
    events
        .expect(|e| matches!(e, Event::HandshakeCompleted { peer: p, .. } if *p == peer))
        .await?;
    Ok(())
}

#[tokio::test]
async fn ipv4_both_directions() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    Ok(())
}

#[tokio::test]
async fn ipv6_both_directions() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    transfer(&a, &mut b, Family::V6, 64).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;
    Ok(())
}

#[tokio::test]
async fn large_packets_arrive_intact() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    for family in [Family::V4, Family::V6] {
        transfer(&a, &mut b, family, 1300).await?;
        transfer(&b, &mut a, family, 1300).await?;
    }
    Ok(())
}

#[tokio::test]
async fn matching_preshared_keys_carry_traffic() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, Some(PSK)).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;

    let peer = a.peer_of(&b).await?;
    let stats = a.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
    assert_eq!(stats.preshared_key, Some(PSK));
    Ok(())
}

#[tokio::test]
async fn mismatched_preshared_keys_reject_the_handshake() -> TestResult {
    let (a, mut b) = channel_pair(Options::default());
    let mut a_drops = a.subscribe().await?;
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;
    introduce_with(&a, &b, Some(PSK), Some([8; 32])).await?;
    let peer = a.peer_of(&b).await?;

    a.send(&a.packet_to(&b, Family::V4, b"secret")).await?;
    // The responder cannot tell: only the initiator fails to open the response.
    a_drops
        .expect(|e| {
            matches!(e, Event::Dropped { peer: Some(p), reason: "handshake rejected" } if *p == peer)
        })
        .await?;
    assert!(a.drops("handshake rejected").await? >= 1);

    b.expect_no_delivery().await?;
    let completed = |e: &Event| matches!(e, Event::HandshakeCompleted { .. });
    a_events.expect_none(completed).await?;
    b_events.expect_none(completed).await?;
    Ok(())
}
