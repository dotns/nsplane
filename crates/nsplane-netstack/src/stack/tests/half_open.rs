//! Inbound handshakes that stay in SYN-RECEIVED: their sockets come back to the listener
//! pool, and one source cannot hold all of it.

use super::labels::{client_turn, connected, send, until_stats};
use super::*;
use crate::Ownership;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
const PORT: u16 = 443;

/// A SYN from `CLIENT:port` whose client then goes silent; the SYN, once the stack
/// answered it.
async fn silent_syn(peer: &mut RawPeer, port: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let socket = peer.connect(LOCAL, PORT, port)?;
    let syn = client_turn(peer).into_iter().next().ok_or("no SYN")?;
    peer.sockets.remove(socket);
    send(&peer.sink, &syn, None).await?;
    timeout(WAIT, async {
        while peer.source.try_admit().is_none() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "the stack should answer the SYN")?;
    Ok(syn)
}

/// Discards what the stack sent, so the client answers none of it.
fn discard_egress(peer: &mut RawPeer) {
    while peer.source.try_admit().is_some() {}
}

#[tokio::test(start_paused = true)]
async fn a_handshake_that_never_completes_gives_its_socket_back() -> TestResult {
    let config = NetStackConfig {
        listener_pool: 2,
        ..config(LOCAL)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 0x4a1f);
    let mut incoming = handle.incoming_tcp();
    let first = silent_syn(&mut peer, 40_300).await?;
    let _second = silent_syn(&mut peer, 40_301).await?;
    assert_eq!(handle.owns(&first), Ownership::Flow);

    // The pool is held: a third SYN is refused.
    let third = peer.connect(LOCAL, PORT, 40_302)?;
    let syn = client_turn(&mut peer).into_iter().next().ok_or("no SYN")?;
    send(&peer.sink, &syn, None).await?;
    until_stats(&handle, |stats| stats.syn_refused == 1).await?;
    peer.sockets.remove(third);

    // Nobody answers the SYN-ACKs. Past the handshake timeout both sockets are back.
    sleep(Duration::from_secs(HANDSHAKE_TIMEOUT.secs() + 5)).await;
    discard_egress(&mut peer);
    assert_eq!(handle.stats().handshake_failed, 2);
    assert_eq!(handle.owns(&first), Ownership::Listener);
    let (_socket, _conn) = connected(&mut peer, &mut incoming, 40_303, None).await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn an_established_connection_outlives_the_handshake_timeout() -> TestResult {
    let (handle, mut peer) = RawPeer::start(config(LOCAL), CLIENT, 0x4a20);
    let mut incoming = handle.incoming_tcp();
    let (socket, conn) = connected(&mut peer, &mut incoming, 40_310, None).await?;
    sleep(Duration::from_secs(HANDSHAKE_TIMEOUT.secs() + 5)).await;
    peer.pump(4).await;
    assert_eq!(peer.state(socket), tcp::State::Established);
    assert!(!*conn.terminal().borrow());
    Ok(())
}
