//! Engine events over an in-memory channel transport: handshake completion, authenticated
//! sources and periodic peer statistics.

use std::time::Duration;

use nsplane::{Event, Peer};
use nsplane_e2e::{Family, Options, TestResult, channel_pair, transfer};

#[tokio::test]
async fn handshake_authentication_and_stats_are_reported() -> TestResult {
    let options = Options {
        stats_interval: Some(Duration::from_millis(100)),
    };
    let (mut a, mut b) = channel_pair(options);
    let mut a_events = a.subscribe().await?;
    let mut b_events = b.subscribe().await?;
    // `b` learns `a`'s address from the handshake.
    a.handle
        .add_or_update_peer(b.as_peer(a.path.transport))
        .await?;
    b.handle
        .add_or_update_peer(Peer {
            path: None,
            ..a.as_peer(b.path.transport)
        })
        .await?;
    let (peer_b, peer_a) = (a.peer_of(&b).await?, b.peer_of(&a).await?);

    transfer(&a, &mut b, Family::V4, 100).await?;
    transfer(&b, &mut a, Family::V6, 200).await?;

    let expected = |node_path: nsplane::Path, via| nsplane::Path {
        transport: via,
        ..node_path
    };
    let b_seen_by_a = expected(b.path, a.path.transport);
    let a_seen_by_b = expected(a.path, b.path.transport);

    a_events
        .expect(|e| {
            matches!(e, Event::HandshakeCompleted { peer, path: Some(path), .. }
                if *peer == peer_b && *path == b_seen_by_a)
        })
        .await?;
    b_events
        .expect(|e| {
            matches!(e, Event::Authenticated { peer, from } if *peer == peer_a && *from == a_seen_by_b)
        })
        .await?;
    b_events
        .expect(|e| {
            matches!(e, Event::HandshakeCompleted { peer, path: Some(path), .. }
                if *peer == peer_a && *path == a_seen_by_b)
        })
        .await?;

    let stats = a_events
        .expect(|e| matches!(e, Event::PeerStats { peer, data_rx, .. } if *peer == peer_b && *data_rx > 0))
        .await?;
    let Event::PeerStats {
        rx,
        tx,
        data_rx,
        last_handshake,
        ..
    } = stats
    else {
        return Err("not a stats event".into());
    };
    // One 100-byte payload went out and one 200-byte payload came in, each in a UDP packet.
    assert_eq!(data_rx, 40 + 8 + 200);
    assert!(tx >= 20 + 8 + 100, "tx {tx}");
    assert!(rx >= data_rx, "rx {rx}");
    assert!(last_handshake.is_some_and(|age| age < Duration::from_secs(5)));

    b_events
        .expect(|e| matches!(e, Event::PeerStats { peer, data_rx, .. } if *peer == peer_a && *data_rx == 20 + 8 + 100))
        .await?;
    Ok(())
}
