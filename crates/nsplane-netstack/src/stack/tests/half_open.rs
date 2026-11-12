//! Inbound handshakes that stay in SYN-RECEIVED: their sockets come back to the listener
//! pool, and one source cannot hold all of it.

use std::net::SocketAddrV4;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

use super::labels::{L1, L2, client_turn, connected, send, until_stats};
use super::*;
use crate::Ownership;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

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

/// A bare SYN from `src` to the stack's [`PORT`], with valid checksums.
fn syn_from(src: SocketAddrV4) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: src.port(),
        dst_port: PORT,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(7_000),
        ack_number: None,
        window_len: u16::MAX,
        window_scale: None,
        max_seg_size: Some(1320),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: *src.ip(),
        dst_addr: LOCAL,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ip.buffer_len() + tcp.buffer_len()];
    let caps = ChecksumCapabilities::default();
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.emit(&mut packet, &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &(*src.ip()).into(),
        &LOCAL.into(),
        &caps,
    );
    bytes
}

/// The flags of the stack's next segment to `client`.
async fn answer_to(peer: &mut RawPeer, client: SocketAddrV4) -> Result<u8, Box<dyn Error>> {
    timeout(WAIT, async {
        loop {
            let packet = peer.source.rx.recv().await.ok_or("the stack stopped")?;
            let (_, dst) = tcp_tuple(packet.as_packet()).ok_or("not TCP")?;
            if dst == SocketAddr::V4(client) {
                let segment = tcp_segment(packet.as_packet()).ok_or("not TCP")?;
                return Ok(segment[13]);
            }
        }
    })
    .await
    .map_err(|_| "the stack should answer the SYN")?
}

/// A stack with a pool of four sockets of which one source may hold `share`.
fn shared_pool(share: Option<usize>) -> NetStackConfig {
    NetStackConfig {
        listener_pool: 4,
        listener_pool_per_source: share,
        ..config(LOCAL)
    }
}

#[tokio::test]
async fn one_source_address_holds_at_most_its_share_of_the_pool() -> TestResult {
    let (handle, mut peer) = RawPeer::start(shared_pool(Some(2)), CLIENT, 0x4a21);
    let flood = |port| SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 66), port);
    for port in [50_000, 50_001] {
        send(&peer.sink, &syn_from(flood(port)), None).await?;
        assert_eq!(answer_to(&mut peer, flood(port)).await?, SYN | ACK);
    }
    // The third handshake of the source is refused, not left to starve the others.
    send(&peer.sink, &syn_from(flood(50_002)), None).await?;
    assert_eq!(answer_to(&mut peer, flood(50_002)).await?, RST | ACK);
    let stats = handle.stats();
    assert_eq!((stats.syn_refused_source, stats.syn_refused), (1, 0));

    // Another source still finds a socket, twice.
    let other = |port| SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 67), port);
    for port in [50_000, 50_001] {
        send(&peer.sink, &syn_from(other(port)), None).await?;
        assert_eq!(answer_to(&mut peer, other(port)).await?, SYN | ACK);
    }
    assert_eq!(handle.stats().syn_refused_source, 1);
    Ok(())
}

#[tokio::test]
async fn the_syns_of_one_batch_count_towards_the_share() -> TestResult {
    let (handle, mut peer) = RawPeer::start(shared_pool(Some(2)), CLIENT, 0x4a22);
    let flood = |port| SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 66), port);
    // Queued without a wait in between: the driver takes them in one turn.
    for port in [50_000, 50_001, 50_002, 50_003] {
        send(&peer.sink, &syn_from(flood(port)), None).await?;
    }
    until_stats(&handle, |stats| stats.syn_refused_source == 2).await?;
    // The refusals leave in the turn's ingest, the SYN-ACKs when smoltcp ran.
    assert_eq!(answer_to(&mut peer, flood(50_003)).await?, RST | ACK);
    assert_eq!(answer_to(&mut peer, flood(50_000)).await?, SYN | ACK);
    Ok(())
}

#[tokio::test]
async fn a_label_is_the_source_where_the_syn_has_one() -> TestResult {
    let (handle, mut peer) = RawPeer::start(shared_pool(Some(1)), CLIENT, 0x4a23);
    let a = SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 66), 50_000);
    let b = SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 67), 50_000);
    let c = SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 67), 50_001);
    send(&peer.sink, &syn_from(a), Some(L1)).await?;
    assert_eq!(answer_to(&mut peer, a).await?, SYN | ACK);
    // The same label from another address is the same source.
    send(&peer.sink, &syn_from(b), Some(L1)).await?;
    assert_eq!(answer_to(&mut peer, b).await?, RST | ACK);
    // Another label from that address is another source.
    send(&peer.sink, &syn_from(c), Some(L2)).await?;
    assert_eq!(answer_to(&mut peer, c).await?, SYN | ACK);
    assert_eq!(handle.stats().syn_refused_source, 1);
    Ok(())
}

#[tokio::test]
async fn a_share_is_free_again_once_its_handshake_ended() -> TestResult {
    let (handle, mut peer) = RawPeer::start(shared_pool(Some(1)), CLIENT, 0x4a24);
    let mut incoming = handle.incoming_tcp();
    // Established, the connection no longer counts.
    let (_socket, _conn) = connected(&mut peer, &mut incoming, 40_320, None).await?;
    let (_socket, _conn) = connected(&mut peer, &mut incoming, 40_321, None).await?;
    assert_eq!(handle.stats().syn_refused_source, 0);
    Ok(())
}

#[tokio::test]
async fn without_a_share_one_source_may_hold_the_whole_pool() -> TestResult {
    let (handle, mut peer) = RawPeer::start(shared_pool(None), CLIENT, 0x4a25);
    let flood = |port| SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 66), port);
    for port in [50_000, 50_001, 50_002, 50_003] {
        send(&peer.sink, &syn_from(flood(port)), None).await?;
        assert_eq!(answer_to(&mut peer, flood(port)).await?, SYN | ACK);
    }
    // The pool itself is the only limit.
    send(&peer.sink, &syn_from(flood(50_004)), None).await?;
    assert_eq!(answer_to(&mut peer, flood(50_004)).await?, RST | ACK);
    let stats = handle.stats();
    assert_eq!((stats.syn_refused_source, stats.syn_refused), (0, 1));
    Ok(())
}
