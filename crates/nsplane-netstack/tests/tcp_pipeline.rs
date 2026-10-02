//! TCP connection establishment through the stack's sink and source with crafted packets.
//!
//! Injecting a valid TCP three-way handshake into the sink must yield a SYN-ACK at the
//! source and a connection on `incoming_tcp`, and data written to the connection must
//! leave through the source.

use std::error::Error;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use futures_core::Stream;
use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_netstack::{NetStack, NetStackConfig, NetStackSink, NetStackSource};
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{IpPacket, TcpHeader, protocol};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(2);
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

// ── packet helpers ────────────────────────────────────────────────────────────

/// Builds an IPv4 or IPv6 TCP packet without options or payload.
fn build_tcp(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&src.port().to_be_bytes());
    segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[8..12].copy_from_slice(&ack.to_be_bytes());
    segment[12] = 0x50; // Data offset 5, no options.
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65535u16.to_be_bytes());
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let sum = transport_checksum_v4(s, d, protocol::TCP, &segment);
            segment[16..18].copy_from_slice(&sum.to_be_bytes());
            let mut pkt = vec![0u8; 20];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = protocol::TCP;
            pkt[12..16].copy_from_slice(&s.octets());
            pkt[16..20].copy_from_slice(&d.octets());
            let sum = ipv4_header_checksum(&pkt);
            pkt[10..12].copy_from_slice(&sum.to_be_bytes());
            pkt.extend_from_slice(&segment);
            Ok(pkt)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let sum = transport_checksum_v6(s, d, protocol::TCP, &segment);
            segment[16..18].copy_from_slice(&sum.to_be_bytes());
            let mut pkt = vec![0u8; 40];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
            pkt[6] = protocol::TCP;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&s.octets());
            pkt[24..40].copy_from_slice(&d.octets());
            pkt.extend_from_slice(&segment);
            Ok(pkt)
        }
        _ => Err("mixed address families".into()),
    }
}

/// TCP flags, seq and ack of a raw IP/TCP packet.
fn parse_tcp(pkt: &[u8]) -> Result<(u8, u32, u32), Box<dyn Error>> {
    let ip = IpPacket::parse(pkt)?;
    let (tcp, _) = TcpHeader::parse(ip.payload())?;
    Ok((tcp.flags(), tcp.seq(), tcp.ack()))
}

/// The TCP payload of a raw IP/TCP packet.
fn tcp_payload(pkt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let ip = IpPacket::parse(pkt)?;
    let (_, payload) = TcpHeader::parse(ip.payload())?;
    Ok(payload.to_vec())
}

/// The advertised TCP MSS (option kind 2), walking the options after the fixed header.
fn parse_tcp_mss(pkt: &[u8]) -> Option<u16> {
    let ip = IpPacket::parse(pkt).ok()?;
    let (tcp, _) = TcpHeader::parse(ip.payload()).ok()?;
    let opts = ip.payload().get(20..tcp.header_len())?;
    let mut idx = 0;
    while idx < opts.len() {
        match opts[idx] {
            0 => break,    // End of options.
            1 => idx += 1, // NOP.
            2 if idx + 3 < opts.len() => {
                return Some(u16::from_be_bytes([opts[idx + 2], opts[idx + 3]]));
            }
            _ if idx + 1 < opts.len() => idx += usize::from(opts[idx + 1].max(2)),
            _ => break,
        }
    }
    None
}

fn start(
    config: NetStackConfig,
) -> (
    nsplane_netstack::NetStackHandle,
    NetStackSource,
    NetStackSink,
) {
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    (handle, source, sink)
}

fn v4(ip: Ipv4Addr, mtu: u16) -> NetStackConfig {
    NetStackConfig::new(vec![(IpAddr::V4(ip), 32)], mtu)
}

async fn inject(sink: &NetStackSink, pkt: &[u8]) -> TestResult {
    sink.send(PacketBuf::from_packet(pkt), PeerId::new(1))
        .await?;
    Ok(())
}

async fn egress(source: &mut NetStackSource) -> Result<PacketBuf, Box<dyn Error>> {
    Ok(timeout(WAIT, source.recv())
        .await
        .map_err(|_| "timed out waiting for egress")??)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// The three-way handshake through the sink produces a connection, and data written to
/// it leaves through the source.
#[tokio::test]
async fn tcp_connection_established_and_data_flows() -> TestResult {
    let vip = Ipv4Addr::new(10, 0, 0, 1);
    let client: SocketAddr = "10.0.0.2:12345".parse()?;
    let server: SocketAddr = "10.0.0.1:8080".parse()?;
    let (handle, mut source, sink) = start(v4(vip, 1360));
    let mut incoming = handle.incoming_tcp();

    // Step 1: SYN.
    inject(&sink, &build_tcp(client, server, 1000, 0, SYN)?).await?;

    // Step 2: SYN-ACK.
    let syn_ack = egress(&mut source).await?;
    let (flags, server_seq, server_ack) = parse_tcp(syn_ack.as_packet())?;
    assert_eq!(flags & (SYN | ACK), SYN | ACK, "expected SYN+ACK flags");
    assert_eq!(server_ack, 1001, "server should ack client ISN+1");

    // Step 3: ACK completes the handshake.
    let ack = build_tcp(client, server, server_ack, server_seq + 1, ACK)?;
    inject(&sink, &ack).await?;

    // Step 4: the connection is accepted.
    let mut conn = timeout(WAIT, poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)))
        .await
        .map_err(|_| "timed out waiting for the connection")?
        .ok_or("incoming_tcp ended")?;
    assert_eq!(conn.local_addr(), server);
    assert_eq!(conn.peer_addr(), client);

    // Step 5: data written to the connection leaves through the source.
    conn.write_all(b"hello").await?;
    conn.flush().await?;
    let data = egress(&mut source).await?;
    assert_eq!(tcp_payload(data.as_packet())?, b"hello");
    Ok(())
}

#[tokio::test]
async fn captured_gateway_syn_receives_syn_ack() -> TestResult {
    let (_handle, mut source, sink) = start(v4(Ipv4Addr::new(10, 0, 0, 119), 1360));

    // Captured from a gateway's wg0 while dialing a live HTTP service:
    // 10.255.0.1:43624 -> 10.0.0.119:80, with TCP options and valid checksums.
    let syn = [
        0x45, 0x00, 0x00, 0x3c, 0x52, 0xb0, 0x40, 0x00, 0x40, 0x06, 0xd2, 0x95, 0x0a, 0xff, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x77, 0xaa, 0x68, 0x00, 0x50, 0x3a, 0x01, 0xdc, 0xad, 0x00, 0x00,
        0x00, 0x00, 0xa0, 0x02, 0xfd, 0x5c, 0x47, 0x0c, 0x00, 0x00, 0x02, 0x04, 0x05, 0x64, 0x04,
        0x02, 0x08, 0x0a, 0xaf, 0xb1, 0x7d, 0x57, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
    ];
    inject(&sink, &syn).await?;

    let syn_ack = egress(&mut source).await?;
    let (flags, _server_seq, server_ack) = parse_tcp(syn_ack.as_packet())?;
    assert_eq!(flags & (SYN | ACK), SYN | ACK, "expected SYN+ACK flags");
    assert_eq!(server_ack, 973_200_558, "server should ack client ISN+1");
    Ok(())
}

/// Regression guard for the tunnel MTU / MSS clamp.
///
/// smoltcp derives the MSS it advertises in the SYN-ACK from the device MTU, which is the
/// configured MTU. The stack sits behind a WireGuard tunnel, so the MSS must leave room
/// for the encapsulation; otherwise the peer sends full-size segments that are
/// black-holed once wrapped (small packets pass, the first ~1.4 KB+ segment stalls, e.g.
/// an SSH post-quantum KEX reply). The advertised MSS must be `mtu - 40` over IPv4 and
/// `mtu - 60` over IPv6, never the 1460 a raw 1500-byte link would advertise.
#[tokio::test]
async fn syn_ack_advertises_wg_safe_mss() -> TestResult {
    for (mtu, client, server, overhead) in [
        (1360u16, "10.0.0.2:33333", "10.0.0.1:80", 40u16),
        (1280, "10.0.0.2:33333", "10.0.0.1:80", 40),
        (1360, "[fd00::2]:33333", "[fd00::1]:80", 60),
        (1280, "[fd00::2]:33333", "[fd00::1]:80", 60),
    ] {
        let client: SocketAddr = client.parse()?;
        let server: SocketAddr = server.parse()?;
        let config = NetStackConfig::new(vec![(server.ip(), 64)], mtu);
        let (_handle, mut source, sink) = start(config);
        inject(&sink, &build_tcp(client, server, 5000, 0, SYN)?).await?;

        let syn_ack = egress(&mut source).await?;
        let (flags, ..) = parse_tcp(syn_ack.as_packet())?;
        assert_eq!(flags & (SYN | ACK), SYN | ACK, "expected SYN+ACK flags");
        let mss = parse_tcp_mss(syn_ack.as_packet()).ok_or("SYN-ACK must carry an MSS option")?;
        assert_eq!(
            mss,
            mtu - overhead,
            "advertised MSS must fit the tunnel MTU"
        );
        assert!(syn_ack.len() <= usize::from(mtu));
    }
    Ok(())
}
