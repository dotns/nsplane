//! `NetStackConfig::max_connections`: the TCP connection limit of every stack.

use super::abort::pump_while;
use super::*;
use crate::TransparentConfig;

const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 9, 32, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 9, 32, 2);

/// Connects a client socket from `port` and returns the stack's connection.
async fn accept(
    peer: &mut RawPeer,
    incoming: &mut (impl Stream<Item = TcpConnection> + Unpin),
    port: u16,
) -> Result<TcpConnection, Box<dyn Error>> {
    peer.connect(LOCAL, 443, port)?;
    let conn = pump_while(peer, &mut Box::pin(next(incoming))).await?;
    Ok(conn.ok_or("the stack stopped")?)
}

#[tokio::test]
async fn a_syn_beyond_max_connections_is_reset_on_a_stack_of_its_own_addresses() -> TestResult {
    let config = NetStackConfig {
        max_connections: Some(1),
        ..config(LOCAL)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 26);
    let mut incoming = handle.incoming_tcp();
    let first = accept(&mut peer, &mut incoming, 40_000).await?;

    // The second connection's SYN, by hand so the answer can be read.
    let second = peer.connect(LOCAL, 443, 40_001)?;
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let syn = peer.device.drain_tx().next().ok_or("no SYN")?;
    let syn_seq = u32::from_be_bytes(syn.as_packet()[24..28].try_into()?);
    peer.sink.send(syn, PeerId::new(0)).await?;
    let reset = timeout(WAIT, peer.source.rx.recv())
        .await?
        .ok_or("no answer")?;
    let (src, dst) = tcp_tuple(reset.as_packet()).ok_or("not TCP")?;
    assert_eq!(src, SocketAddr::new(LOCAL.into(), 443));
    assert_eq!(dst, SocketAddr::new(CLIENT.into(), 40_001));
    let segment = tcp_segment(reset.as_packet()).ok_or("not TCP")?;
    assert_eq!(segment[13], RST | ACK);
    assert_eq!(
        u32::from_be_bytes(segment[8..12].try_into()?),
        syn_seq.wrapping_add(1)
    );
    peer.device.inject(reset);
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    assert_eq!(peer.state(second), tcp::State::Closed);

    // Counted by its reason; the admission counters of transparent mode stay untouched.
    let stats = handle.stats();
    assert_eq!(stats.rejected_connection_limit, 1);
    assert_eq!(stats.accepted, 0);
    assert_eq!(stats.syn_refused, 0);
    assert!(try_next(&mut incoming).is_none());

    // A released connection makes room again.
    let mut terminal = first.terminal();
    first.abort();
    pump_while(
        &mut peer,
        &mut Box::pin(terminal.wait_for(|terminal| *terminal)),
    )
    .await??;
    let _third = accept(&mut peer, &mut incoming, 40_002).await?;
    assert_eq!(handle.stats().rejected_connection_limit, 1);
    Ok(())
}

#[tokio::test]
async fn without_max_connections_a_stack_accepts_past_any_count() -> TestResult {
    let (handle, mut peer) = RawPeer::start(config(LOCAL), CLIENT, 27);
    let mut incoming = handle.incoming_tcp();
    let mut held = Vec::new();
    for port in 40_000..40_040 {
        held.push(accept(&mut peer, &mut incoming, port).await?);
    }
    assert_eq!(held.len(), 40);
    assert_eq!(handle.stats(), NetStackStats::default());
    Ok(())
}

#[test]
fn the_lower_connection_limit_applies_in_transparent_mode() {
    let limit = |stack, transparent| {
        Settings::new(NetStackConfig {
            max_connections: stack,
            transparent: Some(TransparentConfig {
                max_connections: transparent,
                ..Default::default()
            }),
            ..config(LOCAL)
        })
        .max_connections
    };
    assert_eq!(limit(None, None), None);
    assert_eq!(limit(Some(8), None), Some(8));
    assert_eq!(limit(None, Some(4)), Some(4));
    assert_eq!(limit(Some(8), Some(4)), Some(4));
    assert_eq!(limit(Some(2), Some(4)), Some(2));
    let plain = Settings::new(NetStackConfig {
        max_connections: Some(3),
        ..config(LOCAL)
    });
    assert_eq!(plain.max_connections, Some(3));
}
