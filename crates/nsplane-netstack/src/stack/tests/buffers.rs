use std::future::Future;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{Ipv4Packet, TcpPacket, TcpRepr};

use super::*;

/// The configured receive buffer and the window-scale shift and (unscaled) initial window
/// its SYN and SYN-ACK must carry: smoltcp's shift is the buffer's bit length minus 16 (at
/// least 0), and a window in a SYN is never scaled.
const CASES: [(Option<usize>, u8, u16); 3] = [
    // The default at MTU 1360: 1320 * 512 bytes.
    (None, 4, u16::MAX),
    (Some(16 << 10), 0, 16 << 10),
    (Some(4 << 20), 7, u16::MAX),
];

fn config_with(ip: Ipv4Addr, rx_buffer: Option<usize>) -> NetStackConfig {
    NetStackConfig {
        tcp_rx_buffer: rx_buffer,
        ..config(ip)
    }
}

/// The window-scale option and window of the IPv4 TCP segment `packet`.
fn window(packet: &PacketBuf) -> Result<(Option<u8>, u16), Box<dyn Error>> {
    let ip = Ipv4Packet::new_checked(packet.as_packet())?;
    let tcp = TcpPacket::new_checked(ip.payload())?;
    let repr = TcpRepr::parse(
        &tcp,
        &ip.src_addr().into(),
        &ip.dst_addr().into(),
        &ChecksumCapabilities::ignored(),
    )?;
    assert_eq!(repr.control, smoltcp::wire::TcpControl::Syn);
    Ok((repr.window_scale, repr.window_len))
}

#[tokio::test]
async fn syn_ack_window_follows_the_rx_buffer() -> TestResult {
    let server_ip = Ipv4Addr::new(10, 9, 5, 1);
    let client_ip = Ipv4Addr::new(10, 9, 5, 2);
    for (rx_buffer, shift, initial) in CASES {
        let (handle, mut peer) = RawPeer::start(config_with(server_ip, rx_buffer), client_ip, 5);
        let _incoming = handle.incoming_tcp();
        peer.connect(server_ip, 80, 49_400)?;
        peer.pump_once().await;
        let syn_ack = timeout(WAIT, peer.source.rx.recv())
            .await?
            .ok_or("the stack should answer the SYN")?;
        assert_eq!(
            window(&syn_ack)?,
            (Some(shift), initial),
            "rx buffer {rx_buffer:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn syn_window_follows_the_rx_buffer() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 6, 1);
    let remote: SocketAddr = "10.9.6.2:443".parse()?;
    for (rx_buffer, shift, initial) in CASES {
        let (stack, handle) = NetStack::new(config_with(local_ip, rx_buffer));
        let (mut source, _sink) = stack.split();
        let mut connect = Box::pin(handle.connect_tcp(remote));
        assert!(
            Pin::new(&mut connect)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let syn = timeout(WAIT, source.recv()).await??;
        assert_eq!(
            window(&syn)?,
            (Some(shift), initial),
            "rx buffer {rx_buffer:?}"
        );
    }
    Ok(())
}
