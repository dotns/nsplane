//! Both windows closed, with the remote's SND.NXT past the stack's RCV.NXT: the remote sent
//! bytes past the window (as a Linux peer does into a window rounded up to the scale), which
//! the stack trimmed. The remote's ACKs then carry a SEQ past the zero window, and the stack
//! must still take their acknowledgement and window update (RFC 9293 3.10.7.4).

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
use tokio::io::AsyncWriteExt;

use super::*;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 9, 7, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 9, 7, 2);
const LOCAL_PORT: u16 = 80;
const REMOTE_PORT: u16 = 49_700;
const REMOTE_ISN: TcpSeqNumber = TcpSeqNumber(1_000);
/// What the remote first lets the stack send.
const FIRST_WINDOW: u16 = 100;
/// Bytes the remote sent past the stack's window.
const OVERSHOOT: usize = 12;

/// The parts of a stack segment the test follows.
struct Seen {
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    window: u16,
    payload: usize,
}

/// An IPv4 TCP segment from the remote to the stack.
fn segment(
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    window: u16,
    payload: &[u8],
) -> PacketBuf {
    let tcp = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: window,
        window_scale: None,
        max_seg_size: (control == TcpControl::Syn).then_some(1320),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let ip = Ipv4Repr {
        src_addr: REMOTE,
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
        &REMOTE.into(),
        &LOCAL.into(),
        &caps,
    );
    PacketBuf::from_packet(&bytes)
}

/// The next TCP segment the stack sends within `wait`.
async fn next_segment(source: &mut NetStackSource, wait: Duration) -> Option<Seen> {
    let packet = timeout(wait, source.recv()).await.ok()?.ok()?;
    let ip = Ipv4Packet::new_checked(packet.as_packet()).ok()?;
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    let repr = TcpRepr::parse(
        &tcp,
        &ip.src_addr().into(),
        &ip.dst_addr().into(),
        &ChecksumCapabilities::ignored(),
    )
    .ok()?;
    Some(Seen {
        seq: repr.seq_number,
        ack: repr.ack_number,
        window: repr.window_len,
        payload: repr.payload.len(),
    })
}

#[tokio::test]
async fn an_ack_past_a_zero_window_reopens_the_send_window() -> TestResult {
    // Retransmission timers stay out of the way: only the remote's ACK can move data.
    let config = NetStackConfig {
        tcp_rx_buffer: Some(1320),
        tcp_min_rto: Duration::from_secs(10),
        tcp_initial_rto: Duration::from_secs(10),
        ..super::config(LOCAL)
    };
    let (stack, handle) = NetStack::new(config);
    let (mut source, sink) = stack.split();
    let mut incoming = handle.incoming_tcp();
    let send = |packet| sink.send(packet, PeerId::new(0));

    send(segment(TcpControl::Syn, REMOTE_ISN, None, u16::MAX, &[])).await?;
    let syn_ack = next_segment(&mut source, WAIT)
        .await
        .ok_or("the stack should answer the SYN")?;
    let local_isn = syn_ack.seq;
    let mut rcv_nxt = REMOTE_ISN + 1;
    let mut window = syn_ack.window;
    send(segment(
        TcpControl::None,
        rcv_nxt,
        Some(local_isn + 1),
        FIRST_WINDOW,
        &[],
    ))
    .await?;
    let mut conn = timeout(WAIT, next(&mut incoming))
        .await?
        .ok_or("no connection")?;

    // The application writes more than the remote lets through and never reads.
    tokio::spawn(async move {
        let _ = conn.write_all(&[7; 4000]).await;
        std::future::pending::<()>().await;
    });
    let first = next_segment(&mut source, WAIT)
        .await
        .ok_or("the stack should send into the first window")?;
    assert_eq!(
        (first.seq, first.payload),
        (local_isn + 1, usize::from(FIRST_WINDOW))
    );

    // The remote closes its window and fills the stack's, data past it included.
    while window > 0 {
        let len = usize::from(window).min(1320);
        let payload = vec![1; len + OVERSHOOT];
        send(segment(
            TcpControl::None,
            rcv_nxt,
            Some(local_isn + 1),
            0,
            &payload,
        ))
        .await?;
        loop {
            let ack = next_segment(&mut source, WAIT)
                .await
                .ok_or("the stack should acknowledge the data")?;
            if let Some(ack_number) = ack.ack
                && ack_number > rcv_nxt
            {
                rcv_nxt = ack_number;
                window = ack.window;
                break;
            }
        }
    }

    // The remote acknowledges the first window and opens a large one. Its SEQ is its SND.NXT,
    // past the stack's closed window.
    send(segment(
        TcpControl::None,
        rcv_nxt + OVERSHOOT,
        Some(local_isn + 1 + usize::from(FIRST_WINDOW)),
        u16::MAX,
        &[],
    ))
    .await?;
    let data = async {
        loop {
            let seen = next_segment(&mut source, Duration::from_millis(500)).await?;
            if seen.payload > 0 {
                return Some(seen);
            }
        }
    };
    let data = data
        .await
        .ok_or("the stack ignored the ACK past its zero window: the connection is stuck")?;
    assert_eq!(
        data.seq,
        local_isn + 1 + usize::from(FIRST_WINDOW),
        "the acknowledgement was not taken"
    );
    assert!(data.payload > 1, "only a window probe was sent");
    Ok(())
}
