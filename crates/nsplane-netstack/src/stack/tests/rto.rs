use std::future::Future;

use super::*;

/// A configuration whose sockets resend an unanswered SYN or SYN-ACK after 50 ms.
fn config_with_rto(ip: Ipv4Addr) -> NetStackConfig {
    NetStackConfig {
        tcp_min_rto: Duration::from_millis(20),
        tcp_initial_rto: Duration::from_millis(50),
        ..config(ip)
    }
}

/// Well below the default 1 s initial RTO, well above the configured 50 ms.
const RESEND_WITHIN: Duration = Duration::from_millis(500);

#[test]
fn new_sockets_get_the_configured_rto_bounds() {
    let settings = Settings::new(config_with_rto(Ipv4Addr::new(10, 9, 7, 1)));
    let socket = new_tcp_socket(1320, 1320, settings.tcp_rto);
    assert_eq!(socket.min_rto(), SmolDuration::from_millis(20));
    assert_eq!(socket.initial_rto(), SmolDuration::from_millis(50));

    // The defaults are smoltcp's own.
    let settings = Settings::new(NetStackConfig::default());
    let socket = new_tcp_socket(1320, 1320, settings.tcp_rto);
    let default = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 1]),
        tcp::SocketBuffer::new(vec![0; 1]),
    );
    assert_eq!(socket.min_rto(), default.min_rto());
    assert_eq!(socket.initial_rto(), default.initial_rto());
}

#[tokio::test]
async fn connect_resends_the_syn_after_the_initial_rto() -> TestResult {
    let (stack, handle) = NetStack::new(config_with_rto(Ipv4Addr::new(10, 9, 7, 1)));
    let (mut source, _sink) = stack.split();
    let mut connect = Box::pin(handle.connect_tcp("10.9.7.2:443".parse()?));
    assert!(
        Pin::new(&mut connect)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let syn = timeout(WAIT, source.recv()).await??;
    let resent = timeout(RESEND_WITHIN, source.recv()).await??;
    assert_eq!(resent.as_packet(), syn.as_packet());
    Ok(())
}

#[tokio::test]
async fn listener_resends_the_syn_ack_after_the_initial_rto() -> TestResult {
    let server_ip = Ipv4Addr::new(10, 9, 8, 1);
    let (handle, mut peer) =
        RawPeer::start(config_with_rto(server_ip), Ipv4Addr::new(10, 9, 8, 2), 7);
    let _incoming = handle.incoming_tcp();
    peer.connect(server_ip, 80, 49_500)?;
    peer.pump_once().await;
    // The SYN-ACK is never delivered, so the stack resends it.
    let syn_ack = timeout(WAIT, peer.source.rx.recv())
        .await?
        .ok_or("the stack should answer the SYN")?;
    let resent = timeout(RESEND_WITHIN, peer.source.rx.recv())
        .await?
        .ok_or("the stack should resend the SYN-ACK")?;
    assert_eq!(resent.as_packet(), syn_ack.as_packet());
    Ok(())
}
