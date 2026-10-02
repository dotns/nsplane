//! Per-peer counters at engine level, over an in-memory channel transport: `rx`/`tx` count
//! whole datagrams on the wire (handshakes, keepalives, data), `data_rx`/`data_tx` the
//! plaintext IP packets, and the handle and `Event::PeerStats` report the same values.
//!
//! The runtime's clock is paused, so no timer fires between the steps unless a test
//! advances it.

use std::time::Duration;

use nsplane::{ChannelTransport, Event, PeerStats};
use nsplane_e2e::{Family, Node, Options, TestResult, channel_pair, introduce, payload, transfer};
use tokio::time::{advance, sleep};

/// Wire sizes of a handshake initiation, a handshake response and a keepalive.
const INIT: u64 = 148;
const RESPONSE: u64 = 92;
const KEEPALIVE: u64 = 32;
/// The interval of the core's timer tick.
const TICK: Duration = Duration::from_millis(250);
/// How long [`until`] polls, on the paused clock: well below any timer of the tests.
const POLL: Duration = Duration::from_secs(1);

/// `from`'s counters for `to`.
async fn stats(
    from: &Node<ChannelTransport>,
    to: &Node<ChannelTransport>,
) -> TestResult<PeerStats> {
    let peer = from.peer_of(to).await?;
    from.handle
        .peer_stats(peer)
        .await?
        .ok_or_else(|| "unknown peer".into())
}

/// `(rx, tx, data_rx, data_tx)` of `from` for `to`.
async fn counters(
    from: &Node<ChannelTransport>,
    to: &Node<ChannelTransport>,
) -> TestResult<(u64, u64, u64, u64)> {
    let s = stats(from, to).await?;
    Ok((s.rx, s.tx, s.data_rx, s.data_tx))
}

/// Polls `from`'s counters for `to` until `done` holds for them, for at most [`POLL`].
async fn until(
    from: &Node<ChannelTransport>,
    to: &Node<ChannelTransport>,
    mut done: impl FnMut((u64, u64, u64, u64)) -> bool,
) -> TestResult<(u64, u64, u64, u64)> {
    let step = Duration::from_millis(10);
    let mut waited = Duration::ZERO;
    loop {
        let c = counters(from, to).await?;
        if done(c) {
            return Ok(c);
        }
        if waited >= POLL {
            return Err(format!("counters {c:?} after {POLL:?}").into());
        }
        sleep(step).await;
        waited += step;
    }
}

/// Both ends agree when nothing is lost.
async fn assert_agree(a: &Node<ChannelTransport>, b: &Node<ChannelTransport>) -> TestResult {
    let (a_rx, a_tx, a_data_rx, a_data_tx) = counters(a, b).await?;
    let (b_rx, b_tx, b_data_rx, b_data_tx) = counters(b, a).await?;
    assert_eq!((a_tx, a_rx), (b_rx, b_tx));
    assert_eq!((a_data_tx, a_data_rx), (b_data_rx, b_data_tx));
    Ok(())
}

/// Two linked peers after one handshake `a` initiated, confirmed by `a`'s keepalive.
async fn handshaken(
    options: Options,
) -> TestResult<(Node<ChannelTransport>, Node<ChannelTransport>)> {
    let (a, b) = channel_pair(options);
    introduce(&a, &b, None).await?;
    a.handle.force_handshake(a.peer_of(&b).await?, None).await?;
    until(&b, &a, |(rx, ..)| rx == INIT + KEEPALIVE).await?;
    Ok((a, b))
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn handshakes_and_keepalives_count_on_both_ends() -> TestResult {
    let (a, b) = handshaken(Options::default()).await?;
    assert_eq!(counters(&a, &b).await?, (RESPONSE, INIT + KEEPALIVE, 0, 0));
    assert_eq!(counters(&b, &a).await?, (INIT + KEEPALIVE, RESPONSE, 0, 0));
    assert_agree(&a, &b).await?;

    // Enabling a persistent keepalive sends one on the next tick, the next one only after
    // the interval.
    a.handle.set_keepalive(b.public(), Some(25)).await?;
    advance(TICK).await;
    until(&b, &a, |(rx, ..)| rx == INIT + 2 * KEEPALIVE).await?;
    assert_eq!(
        counters(&a, &b).await?,
        (RESPONSE, INIT + 2 * KEEPALIVE, 0, 0)
    );
    assert_agree(&a, &b).await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn packets_count_padded_on_the_wire_and_plain_as_data() -> TestResult {
    let (mut a, mut b) = handshaken(Options::default()).await?;
    for (family, len) in [(Family::V4, 64), (Family::V6, 1300), (Family::V4, 1)] {
        // An IP packet of n bytes is padded to a multiple of 16 and sealed behind a 16-byte
        // header and a 16-byte tag.
        let n = u64::try_from(a.packet_to(&b, family, &payload(len)).len())?;
        let wire = KEEPALIVE + n.next_multiple_of(16);

        let (a_rx, a_tx, a_data_rx, a_data_tx) = counters(&a, &b).await?;
        transfer(&a, &mut b, family, len).await?;
        assert_eq!(
            counters(&a, &b).await?,
            (a_rx, a_tx + wire, a_data_rx, a_data_tx + n),
            "{family:?} packet of {n} bytes"
        );
        transfer(&b, &mut a, family, len).await?;
        assert_eq!(
            counters(&a, &b).await?,
            (a_rx + wire, a_tx + wire, a_data_rx + n, a_data_tx + n),
            "{family:?} packet of {n} bytes"
        );
        assert_agree(&a, &b).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn handle_views_and_stats_events_agree() -> TestResult {
    let (mut a, mut b) = handshaken(Options {
        stats_interval: Some(Duration::from_secs(1)),
    })
    .await?;
    transfer(&a, &mut b, Family::V4, 100).await?;
    transfer(&b, &mut a, Family::V6, 200).await?;
    let peer_b = a.peer_of(&b).await?;
    let mut events = a.subscribe().await?;

    let expected = counters(&a, &b).await?;
    let (rx, tx, data_rx, data_tx) = expected;
    assert!(rx > data_rx && data_rx > 0 && tx > data_tx && data_tx > 0);
    let [peer] = <[PeerStats; 1]>::try_from(a.handle.peers().await?)
        .map_err(|peers| format!("expected one peer, got {peers:?}"))?;
    assert_eq!(peer.peer, peer_b);
    assert_eq!((peer.rx, peer.tx, peer.data_rx, peer.data_tx), expected);

    let event = events
        .expect(|e| matches!(e, Event::PeerStats { peer, .. } if *peer == peer_b))
        .await?;
    let Event::PeerStats {
        rx,
        tx,
        data_rx,
        data_tx,
        ..
    } = event
    else {
        return Err("not a stats event".into());
    };
    assert_eq!((rx, tx, data_rx, data_tx), expected);
    Ok(())
}
